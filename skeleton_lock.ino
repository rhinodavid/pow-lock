#include "EEPROM.h"
#include "mbedtls/md.h"
#include <WiFi.h>
#include "secrets.h"

#define EEPROM_SIZE 256
#define BASE_SIZE 8
#define ADDR 0
#define PORT_NUMBER 6969 // for server
#define MAX_INPUT 16     // tcp message max length

byte randomValue;
char letter;
char base[BASE_SIZE + 1];
byte shaResult[32];
byte nonceBytes[4];
byte payload[BASE_SIZE + 4];
unsigned int nonce = 255;
mbedtls_md_context_t ctx;
mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

WiFiServer wifiServer(PORT_NUMBER);
WiFiClient client;

void setup()
{
  randomSeed(analogRead(0));

  Serial.begin(115200);
  while (!Serial)
    ;

  // EEPROM
  if (!EEPROM.begin(EEPROM_SIZE))
  {
    Serial.println("failed to initialise EEPROM");
    delay(1000000);
  }
  delay(100);

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

  // HASHING
  strcpy(base, "abcdabcd");
  set_nonce(nonce, nonceBytes);
  set_nonce(256, nonceBytes);
  set_nonce(4294967295, nonceBytes);

  build_payload();
  hash_payload();

  Serial.println("start...");
  delay(3000);
}
void loop()
{
  check_client_input();
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
        processIncomingByte(client.read());
      }
      delay(10);
    }
    client.stop();
    Serial.println("Client disconnected");
  }
}

// from: http://www.gammon.com.au/serial
void process_data(const char *data)
{
  // for now just display it
  // (but you could compare it to some value, convert to an integer, etc.)
  Serial.println(data);
}

// from: http://www.gammon.com.au/serial
void processIncomingByte(const byte inByte)
{
  static char input_line[MAX_INPUT];
  static unsigned int input_pos = 0;

  switch (inByte)
  {
  case '\n':                   // end of text
    input_line[input_pos] = 0; // terminating null byte
    // terminator reached! process input_line here ...
    process_data(input_line);
    // reset buffer for next time
    input_pos = 0;
    break;

  case '\r': // discard carriage return
    break;

  default:
    // keep adding if not full ... allow for terminating null byte
    if (input_pos < (MAX_INPUT - 1))
      input_line[input_pos++] = inByte;
    break;
  }

  // switch (inByte)
  // {
  // case 'F':
  // case 'f':
  //   client.println("flash!");
  //   break;
  // default:
  //   break;
  // }
  // return client;
}

// HASHING
/*
 * Hashing steps:
 * Set base -- ex: strcpy(base, "abcdabcd")
 * Set nonce -- set_nonce((unsigned int)4294967295, nonceBytes)
 * Build payload -- build_payload()
 * Hash payload -- hash_payload()
 */

void set_nonce(unsigned int nonce, byte buf[4])
{
  buf[0] = (byte)nonce;
  buf[1] = (byte)(nonce >> 8);
  buf[2] = (byte)(nonce >> 16);
  buf[3] = (byte)(nonce >> 24);
  Serial.print("Setting nonce to hex: ");
  for (int i = 0; i < 4; i++)
  {
    char str[3];
    sprintf(str, "%02x", (int)buf[i]);
    Serial.print(str);
  }
  Serial.print("\n");
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
  for (int i = 0; i < sizeof(payload); i++)
  {
    char str[3];
    sprintf(str, "%02x", (int)payload[i]);
    Serial.print(str);
  }
  Serial.println("\n");
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
  for (int i = 0; i < sizeof(shaResult); i++)
  {
    char str[3];
    sprintf(str, "%02x", (int)shaResult[i]);
    Serial.print(str);
  }
  Serial.print("\n");
}

// STRING SAVE

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

void save_base()
{
  Serial.print("Saving base: ");
  Serial.println(base);
  EEPROM.writeBytes(ADDR, base, BASE_SIZE);
  EEPROM.commit();
  delay(2500);
  Serial.println("Saved");
}

void read_saved_base()
{
  EEPROM.readBytes(ADDR, base, BASE_SIZE);
  delay(1000);
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
