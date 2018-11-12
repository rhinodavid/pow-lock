#include "EEPROM.h"
#include "mbedtls/md.h"
#include <WiFi.h>
#include "secrets.h"

#define EEPROM_SIZE 256
#define BASE_SIZE 32
#define ADDR 0                      // address to save target; base will be saved + 32
#define PORT_NUMBER 6969            // for server
#define MAX_INPUT 66                // tcp message max length [command][target in hex (64)][\0]
#define LATCH_ACTUATION_TIME_MS 125 // how long the latch pin is energized when opening
#define NONCE_BYTE_SIZE 8           // rust u64 is 8 bytes

#define INDICATOR_LED_PIN 21
#define RESET_SWITCH_PIN 27
#define OPEN_SWITCH_PIN 19
#define LATCH_PIN 9

static volatile bool openPressed = false;
static volatile bool resetPressed = false;
byte nonceBytes[NONCE_BYTE_SIZE];
byte payload[BASE_SIZE + NONCE_BYTE_SIZE];
byte randomValue;
byte shaResult[32];
byte target[32];
char base[BASE_SIZE + 1];
char letter;

mbedtls_md_context_t ctx;
mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

WiFiServer wifiServer(PORT_NUMBER);
WiFiClient client;

enum Status
{
  UNLOCKED = 0,
  LOCKED = 1,
  UNKNOWN = 2
};

Status status = UNKNOWN;

// Interrupt handlers

void IRAM_ATTR handle_reset_interrupt()
{
  resetPressed = true;
}

void IRAM_ATTR handle_open_interrupt()
{
  openPressed = true;
}

void setup()
{
  randomSeed(analogRead(0));
  Serial.begin(115200);
  while (!Serial)
    ;

  delay(2000);
  // EEPROM
  if (!EEPROM.begin(EEPROM_SIZE))
  {
    Serial.println("Failed to initialize EEPROM");
    delay(1000000);
  }
  delay(100);

  // GPIO
  pinMode(RESET_SWITCH_PIN, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(RESET_SWITCH_PIN), handle_reset_interrupt, FALLING);
  pinMode(OPEN_SWITCH_PIN, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(OPEN_SWITCH_PIN), handle_open_interrupt, FALLING);
  pinMode(LATCH_PIN, OUTPUT);
  digitalWrite(LATCH_PIN, LOW);
  pinMode(INDICATOR_LED_PIN, OUTPUT);
  digitalWrite(INDICATOR_LED_PIN, LOW);

  // WiFi
  Serial.println("Starting up wifi");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(1000);
    flash_indicator_led_high_low(/* times= */ 2, /* delay_ms= */ 200);
    delay(8000);
    Serial.println("Connecting to WiFi..");
  }
  Serial.print("Connected to the WiFi network with IP: ");
  flash_indicator_led_high_low(/* times= */ 1, /* delay_ms= */ 500);
  Serial.println(WiFi.localIP());

  wifiServer.begin();

  // Status
  read_saved_base();
  read_saved_target();

  if (is_base_zeroized())
  {
    status = UNLOCKED;
    Serial.println("Starting Unlocked");
  }
  else
  {
    status = LOCKED;
    Serial.println("Starting Locked");
  }

  flash_indicator_led_high_low(/* times= */ 10, /* delay_ms= */ 32);
  Serial.println("Setup complete");
}

void loop()
{
  update_status_led();
  check_open_pressed();
  check_reset_pressed();
  check_client_input();
}

void check_open_pressed()
{
  if (openPressed)
  {
    openPressed = false;
    if (status == UNLOCKED)
    {
      Serial.println("Open button pressed; opening");
      open();
    }
    else
    {
      Serial.println("Open button pressed while locked");
    }
  }
}

void check_reset_pressed()
{
  if (resetPressed)
  {
    resetPressed = false;
    Serial.println("Reset button pressed; unlocking/resetting");
    unlock();
  }
}

// Business
void unlock()
{
  Serial.println("Unlocking...");
  flash_indicator_led_high_low(/* times= */ 7, /* delay_ms= */ 50);
  zeroize_base();
  save_base();
  zeroize_target();
  save_target();
  status = UNLOCKED;
  Serial.println("Unlocked...");
}

void open()
{
  digitalWrite(LATCH_PIN, HIGH);
  digitalWrite(INDICATOR_LED_PIN, LOW);
  delay(LATCH_ACTUATION_TIME_MS);
  digitalWrite(INDICATOR_LED_PIN, HIGH);
  digitalWrite(LATCH_PIN, LOW);
}

void update_status_led()
{
  if (status == UNLOCKED)
  {
    digitalWrite(INDICATOR_LED_PIN, HIGH);
  }
  else
  {
    digitalWrite(INDICATOR_LED_PIN, LOW);
  }
}

void zeroize_target()
{
  memset(target, 0, 32);
}

bool check_hash_against_target()
{
  Serial.print("Checking hash:\n\t");
  print_bytes_as_hex(shaResult, 32);
  Serial.print("Against target:\n\t");
  print_bytes_as_hex(target, 32);
  int target_byte;
  int answer_byte;
  for (int i = 0; i < 32; i++)
  {
    answer_byte = (int)shaResult[i];
    target_byte = (int)target[i];
    if (target_byte > answer_byte)
      return true;
    if (answer_byte > target_byte)
      return false;
  }
  // they are the same
  return false;
}

void print_bytes_as_hex(const byte *val, int len)
{
  for (int i = 0; i < len; i++)
  {
    char str[3];
    sprintf(str, "%02x", (int)val[i]);
    Serial.print(str);
  }
  Serial.print("\n");
}

void randomize_base()
{
  memset(base, '\0', strlen(base));
  for (int i = 0; i < BASE_SIZE; i++)
  {
    do
    {
      randomValue = random(48, 122);
    } while (randomValue == 92 /* backslash */ ||
             randomValue == 96 /* backtick */);
    base[i] = randomValue;
  }
  delay(1000);
}

void zeroize_base()
{
  memset(base, '0', strlen(base));
}

bool is_base_zeroized()
{
  for (int i = 0; i < BASE_SIZE; i++)
  {
    if (base[i] != '0')
    {
      return false;
    }
  }
  return true;
}

void flash_indicator_led_high_low(int times, int delay_ms)
{
  for (int x = 0; x < times; x++)
  {
    digitalWrite(INDICATOR_LED_PIN, HIGH);
    delay(delay_ms);
    digitalWrite(INDICATOR_LED_PIN, LOW);
    delay(delay_ms);
  }
}

// Networking
void check_client_input()
{
  client = wifiServer.available();

  if (client)
  {
    while (client.connected())
    {
      while (client.available() > 0)
      {
        process_incoming_byte(client.read());
      }
      delay(10);
    }
    client.stop();
    Serial.println("Client disconnected");
  }
}

void process_data(const char *data)
{
  /*
   * Commands:
   *    Open (O): If the device is unlocked, commands the latch opened
   *    Lock (L<target>): Sets the given target and locks the device
   *        target: the 256-bit target as lowercase hex
   *        EX: "L00000000ffff0000000000000000000000000000000000000000000000000000\n"
   *    Unlock (U<nonce>): Attempts to unlock the device with the given nonce
   *        The hash of base+nonce must be less than the target hash
   *        The nonce is expressed in hexadecimal
   *        EX: "U0b00c0008f00141a"
   *    Get Base (B): Asks for the current base
   *        Response: <base>
   *    Get target (D): Asks for the current target
   *        Response: <target>
   *    Get Status (S): Asks for the current status of the lock 
   *        Response: 0 - unlocked, 1 - locked, 2 - unknown
   */
  char input_data[MAX_INPUT - 1];
  char hex[2];
  unsigned long val;

  switch (data[0])
  {
  case 'o':
  case 'O':
    Serial.println("Open");
    if (status == UNLOCKED)
    {
      client.println("1");
      open();
    }
    else
    {
      client.println("ERROR: Attempted to open when not unlocked");
      Serial.println("Attempted to open when not unlocked");
    }
    break;
  case 'l':
  case 'L':
    memcpy(input_data, data + 1, MAX_INPUT - 2);
    Serial.println("Lock");
    Serial.println(input_data);
    if (status == UNLOCKED)
    {
      // save target
      for (int i = 0; i < 32; i++)
      {
        hex[0] = input_data[i * 2];
        hex[1] = input_data[i * 2 + 1];
        val = strtoul(hex, nullptr, /* BASE = */ 16);
        target[i] = (byte)val;
      }
      save_target();

      // make new base
      randomize_base();
      save_base();
      client.println(base);
      status = LOCKED;
    }
    else
    {
      client.println("ERROR: Attempted to lock when already locked");
      Serial.println("Attempted to lock when already locked");
    }
    break;
  case 'u':
  case 'U':
    memcpy(input_data, data + 1, MAX_INPUT - 2);
    Serial.print("Unlock with: ");
    Serial.println(input_data);
    if (status == LOCKED)
    {
      Serial.println(strlen(input_data));
      if (strlen(input_data) != NONCE_BYTE_SIZE * 2)
      {
        client.print("ERROR: Expected ");
        client.print(NONCE_BYTE_SIZE * 2);
        client.print(" chars to represent nonce in hex format.");
        Serial.print("Incorrect nonce format; received: ");
        Serial.println(input_data);
        return;
      }
      for (int i = 0; i < NONCE_BYTE_SIZE; i++)
      {
        hex[0] = input_data[i * 2];
        hex[1] = input_data[i * 2 + 1];
        val = strtoul(hex, nullptr, /* BASE = */ 16);
        nonceBytes[i] = (byte)val;
      }
      Serial.print("Nonce set to hex: ");
      print_bytes_as_hex(nonceBytes, NONCE_BYTE_SIZE);
      build_payload();
      hash_payload();
      bool isValid = check_hash_against_target();
      if (isValid)
      {
        client.println("1");
        unlock();
      }
      else
      {
        client.println("0");
        Serial.println("Result hash not less than target");
      }
    }
    else
    {
      client.println("ERROR: Attempted to unlock when not locked");
      Serial.println("Attempted to unlock when not locked");
    }
    break;
  case 'b':
  case 'B':
    Serial.println("Get Base");
    if (status == LOCKED)
    {
      client.println(base);
      Serial.print("Base is: ");
      Serial.println(base);
    }
    else
    {
      client.println("ERROR: Attempted to get base when not locked");
      Serial.println("Attempted to get base when not locked");
    }
    break;
  case 't':
  case 'T':
    Serial.println("Get target");
    if (status == LOCKED)
    {
      for (int i = 0; i < 32; i++)
      {
        char str[3];
        sprintf(str, "%02x", (int)target[i]);
        client.print(str);
      }
      client.print("\n");
    }
    else
    {
      client.println("ERROR: Attempted to get target when not locked");
      Serial.println("Attempted to get target when not locked");
    }
    break;
  case 's':
  case 'S':
    Serial.println("Get Status");
    Serial.print("Status: ");
    Serial.println(status);
    client.println(status);
    break;
  default:
    Serial.print("Unknown Command: ");
    Serial.println(data);
    client.print("ERROR: Unknown command: ");
    client.println(data);
    break;
  }
}

// see: http://www.gammon.com.au/serial
void process_incoming_byte(const byte inByte)
{
  static char input_line[MAX_INPUT];
  static unsigned int input_pos = 0;

  switch (inByte)
  {
  case '\n':           // end of text
    if (input_pos > 0) // only do something if it wasn't just a newline
    {
      input_line[input_pos] = 0; // terminating null byte
      // terminator reached! process input_line here ...
      process_data(input_line);
      // reset buffer for next time
      input_pos = 0;
    }
    break;

  case '\r': // discard carriage return
    break;

  default:
    // keep adding if not full ... allow for terminating null byte
    if (input_pos < (MAX_INPUT - 1))
      input_line[input_pos++] = inByte;
    break;
  }
}

// HASHING
void build_payload()
{
  size_t len = BASE_SIZE;
  for (int i = 0; i < len; i++)
  {
    payload[i] = base[i];
  }
  for (int j = 0; j < NONCE_BYTE_SIZE; j++)
  {
    payload[j + len] = nonceBytes[j];
  }

  Serial.print("Built payload: ");
  print_bytes_as_hex(payload, sizeof(payload));
}

void hash_payload()
{
  Serial.print("Hashed: ");
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char *)payload, BASE_SIZE + NONCE_BYTE_SIZE);
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);
  print_bytes_as_hex(shaResult, sizeof(shaResult));
}

// STRING SAVE
void save_base()
{
  Serial.print("Saving base: ");
  Serial.println(base);
  EEPROM.writeBytes(ADDR + 32, base, BASE_SIZE);
  EEPROM.commit();
  delay(500);
  Serial.println("Saved");
}

void read_saved_base()
{
  Serial.print("Reading base: ");
  EEPROM.readBytes(ADDR + 32, base, BASE_SIZE);
  Serial.println(base);
}

void save_target()
{
  Serial.print("Saving target: ");
  print_bytes_as_hex(target, 32);
  EEPROM.writeBytes(ADDR, target, 32);
  EEPROM.commit();
  delay(500);
  Serial.println("Saved");
}

void read_saved_target()
{
  Serial.print("Reading target: ");
  EEPROM.readBytes(ADDR, target, 32);
  print_bytes_as_hex(target, 32);
}
