#include "EEPROM.h"
#include "mbedtls/md.h"
#include <WiFi.h>
#include "secrets.h"

#define EEPROM_SIZE 256
#define BASE_SIZE 32
#define ADDR 0           // address to save target; base will be saved + 32
#define PORT_NUMBER 6969 // for server
#define MAX_INPUT 66     // tcp message max length [command][target in hex (64)][\0]

#define BUILT_IN_LED 2
#define RESET_SWITCH_PIN 36
#define OPEN_SWITCH_PIN 39
#define LATCH_PIN 23

bool openPressed = false;
bool resetPressed = false;
byte nonceBytes[4];
byte payload[BASE_SIZE + 4];
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
  attachInterrupt(digitalPinToInterrupt(RESET_SWITCH_PIN), handle_reset_inturrupt, LOW);
  pinMode(OPEN_SWITCH_PIN, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(OPEN_SWITCH_PIN), handle_open_inturrupt, LOW);
  pinMode(LATCH_PIN, OUTPUT);
  digitalWrite(LATCH_PIN, LOW);
  pinMode(BUILT_IN_LED, OUTPUT);
  digitalWrite(BUILT_IN_LED, LOW);

  // WiFi
  Serial.println("Starting up wifi");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(1000);
    Serial.println("Connecting to WiFi..");
  }
  Serial.print("Connected to the WiFi network with IP: ");
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
  Serial.println("Setup complete");
}
void loop()
{
  update_status_led();
  check_open_pressed();
  check_reset_pressed();
  check_client_input();
}

// Inturrputs

void handle_reset_inturrupt()
{
  resetPressed = true;
}

void handle_open_inturrupt()
{
  openPressed = true;
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
  zeroize_base();
  save_base();
  zeroize_target();
  save_target();
  status = UNLOCKED;
  Serial.println("Unlocked...");
}

void open()
{
  Serial.println("Opening");
  digitalWrite(LATCH_PIN, HIGH);
  delay(500);
  digitalWrite(LATCH_PIN, LOW);
}

void update_status_led()
{
  if (status == UNLOCKED)
  {
    digitalWrite(BUILT_IN_LED, HIGH);
  }
  else
  {
    digitalWrite(BUILT_IN_LED, LOW);
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
    randomValue = random(48, 122);
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
      open();
    }
    else
    {
      client.println("ERROR: Device locked");
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
      client.println("ERROR: Already locked");
      Serial.println("Attempted to lock when not unlocked");
    }
    break;
  case 'u':
  case 'U':
    memcpy(input_data, data + 1, MAX_INPUT - 2);
    Serial.println("Unlock");
    Serial.println(input_data);
    if (status == LOCKED)
    {
      unsigned int inputNonce = atoi(input_data);
      Serial.println("Attempting to set nonce to:");
      Serial.println(inputNonce);
      set_nonce(inputNonce);
      build_payload();
      hash_payload();
      bool isValid = check_hash_against_target();
      if (isValid)
      {
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
      client.println("1");
      Serial.println("Attempted to unlock when not locked");
    }
    break;
  case 'b':
  case 'B':
    Serial.println("Get Base");
    client.println(base);
    break;
  case 't':
  case 'T':
    Serial.println("Get target");
    for (int i = 0; i < 32; i++)
    {
      char str[3];
      sprintf(str, "%02x", (int)target[i]);
      client.print(str);
    }
    client.print("\n");
    break;
  case 's':
  case 'S':
    Serial.println("Get Status");
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

// from: http://www.gammon.com.au/serial
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
/*
 * Hashing steps:
 * Set base -- ex: strcpy(base, "abcdabcd")
 * Set nonce -- set_nonce((unsigned int)4294967295)
 * Build payload -- build_payload()
 * Hash payload -- hash_payload()
 */

void set_nonce(unsigned int nonce)
{
  nonceBytes[0] = (byte)nonce;
  nonceBytes[1] = (byte)(nonce >> 8);
  nonceBytes[2] = (byte)(nonce >> 16);
  nonceBytes[3] = (byte)(nonce >> 24);
  Serial.print("Setting nonce to hex: ");
  print_bytes_as_hex(nonceBytes, 4);
}

void build_payload()
{
  size_t len = BASE_SIZE;
  for (int i = 0; i < len; i++)
  {
    payload[i] = base[i];
  }
  for (int j = 0; j < 4; j++)
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
  mbedtls_md_update(&ctx, (const unsigned char *)payload, BASE_SIZE + 4);
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
