#include "EEPROM.h"
#include "mbedtls/md.h"
#include <WiFi.h>

#define EEPROM_SIZE 256
#define BASE_SIZE 8
#define ADDR 0
#define PORT_NUMBER 6969 // for server

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
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED)
  {
    delay(1000);
    Serial.println("Connecting to WiFi..");
  }

  Serial.println("Connected to the WiFi network");
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
