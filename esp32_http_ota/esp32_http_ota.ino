// ESP32-S3 HTTPS OTA istemcisi (Laravel API + SHA-256 dogrulama)
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <ArduinoJson.h>      // Library Manager: "ArduinoJson" (v7)
#include <mbedtls/md.h>

// ======================= AYARLAR =======================
// Admin panelde yukledigin "Version" ile BIREBIR ayni olmali (ornek: 1.0.3)
#define FIRMWARE_VERSION "1.0.2"

const char *WIFI_SSID = "DORA";
const char *WIFI_PASS = "12345678";

const char *API_URL = "https://www.mehmetdora.me/api/esp32/firmware";

const uint32_t CHECK_INTERVAL_MS = 60000;   // kontrol araligi (60 sn)
const uint32_t BLINK_MS = 2000;

// 1 = sertifika dogrulamasi yok (kolay baslangic), 0 = ROOT_CA ile dogrula
#define USE_INSECURE_TLS 1
// =======================================================

#if !USE_INSECURE_TLS
// Sitenin zincirindeki kok sertifika (PEM). Tarayicidan sertifika bilgisine bakip ekle.
const char *ROOT_CA = R"EOF(
-----BEGIN CERTIFICATE-----
BURAYA_KOK_SERTIFIKA
-----END CERTIFICATE-----
)EOF";
#endif

uint32_t lastCheck = 0;
bool firstCheckDone = false;
uint32_t lastBlink = 0;

void setupTLS(WiFiClientSecure &c) {
#if USE_INSECURE_TLS
  c.setInsecure();
#else
  c.setCACert(ROOT_CA);
#endif
}

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("WiFi baglaniyor");
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) {
    delay(500);
    Serial.print(".");
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.printf("\nBaglanamadi (durum %d), yeniden baslatiliyor\n", WiFi.status());
    delay(3000);
    ESP.restart();
  }
  Serial.printf("\nBaglandi, IP: %s\n", WiFi.localIP().toString().c_str());

#if !USE_INSECURE_TLS
  // Sertifika dogrulamasi icin saat gerekir
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  time_t now = 0;
  uint32_t t1 = millis();
  while (now < 1700000000 && millis() - t1 < 15000) {
    delay(300);
    time(&now);
  }
#endif
}

// Firmware'i indirir, SHA-256'yi dogrular, dogruysa yazip yeniden baslatir.
bool downloadAndInstall(const String &binUrl, const String &expectedSha) {
  WiFiClientSecure client;
  setupTLS(client);
  HTTPClient http;
  http.setTimeout(15000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  if (!http.begin(client, binUrl)) {
    Serial.println("Indirme baslatilamadi");
    return false;
  }

  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    Serial.printf("Indirme hatasi, HTTP kodu: %d\n", code);
    http.end();
    return false;
  }

  int total = http.getSize();
  if (total <= 0) {
    Serial.println("Dosya boyutu alinamadi");
    http.end();
    return false;
  }
  Serial.printf("Firmware boyutu: %d bayt\n", total);

  if (!Update.begin(total)) {
    Serial.print("Update.begin hatasi: ");
    Update.printError(Serial);
    http.end();
    return false;
  }

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&ctx);

  WiFiClient *stream = http.getStreamPtr();
  uint8_t buf[1024];
  int written = 0;
  int lastPercent = -1;
  uint32_t lastData = millis();
  bool ok = true;

  while (written < total) {
    size_t avail = stream->available();
    if (avail) {
      size_t n = stream->readBytes(buf, min(avail, sizeof(buf)));
      mbedtls_md_update(&ctx, buf, n);
      if (Update.write(buf, n) != n) {
        Serial.print("Yazma hatasi: ");
        Update.printError(Serial);
        ok = false;
        break;
      }
      written += n;
      lastData = millis();

      int percent = (written * 100) / total;
      if (percent != lastPercent && percent % 10 == 0) {
        Serial.printf("Indiriliyor: %%%d\n", percent);
        lastPercent = percent;
      }
    } else {
      if (millis() - lastData > 15000) {
        Serial.println("Indirme zaman asimina ugradi");
        ok = false;
        break;
      }
      if (!stream->connected() && !stream->available()) {
        Serial.println("Baglanti koptu");
        ok = false;
        break;
      }
      delay(1);
    }
  }

  uint8_t hash[32];
  mbedtls_md_finish(&ctx, hash);
  mbedtls_md_free(&ctx);
  http.end();

  if (ok && written != total) {
    Serial.printf("Eksik indirme: %d / %d\n", written, total);
    ok = false;
  }

  if (ok) {
    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", hash[i]);
    hex[64] = 0;
    Serial.printf("Hesaplanan SHA-256: %s\n", hex);
    Serial.printf("Beklenen SHA-256  : %s\n", expectedSha.c_str());

    if (!expectedSha.equalsIgnoreCase(String(hex))) {
      Serial.println("SHA-256 UYUSMUYOR, guncelleme iptal edildi.");
      ok = false;
    }
  }

  if (!ok) {
    Update.abort();
    return false;
  }

  if (!Update.end(true)) {
    Serial.print("Update.end hatasi: ");
    Update.printError(Serial);
    return false;
  }

  Serial.println("Guncelleme basarili, yeniden baslatiliyor...");
  delay(500);
  ESP.restart();
  return true;
}

void checkForUpdate() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi yok, yeniden baglaniliyor");
    WiFi.reconnect();
    return;
  }

  WiFiClientSecure client;
  setupTLS(client);
  HTTPClient http;
  http.setTimeout(10000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  String url = String(API_URL) + "?version=" + FIRMWARE_VERSION;
  if (!http.begin(client, url)) {
    Serial.println("HTTP baslatilamadi");
    return;
  }
  http.addHeader("Accept", "application/json");

  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    Serial.printf("Surum sorgusu basarisiz, HTTP kodu: %d\n", code);
    http.end();
    return;
  }
  String body = http.getString();
  http.end();

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, body);
  if (err) {
    Serial.printf("JSON hatasi: %s\n", err.c_str());
    return;
  }

  bool available = doc["update_available"] | false;
  String serverVer = doc["version"] | "";
  Serial.printf("Cihaz surumu: %s, sunucu surumu: %s\n", FIRMWARE_VERSION, serverVer.c_str());

  if (!available) {
    Serial.println("Guncel.");
    return;
  }

  String binUrl = doc["url"] | "";
  String sha = doc["sha256"] | "";

  if (binUrl.isEmpty() || sha.length() != 64 || !binUrl.startsWith("https://")) {
    Serial.println("API cevabi gecersiz (url/sha256), guncelleme yapilmadi.");
    return;
  }
  if (serverVer == FIRMWARE_VERSION) {
    return;
  }

  Serial.printf("Yeni surum bulundu (%s), indiriliyor...\n", serverVer.c_str());
  downloadAndInstall(binUrl, sha);
}

void setup() {
  Serial.begin(115200);
  delay(1500);
  Serial.println("\n=============================");
  Serial.printf("HTTPS OTA istemcisi - SURUM %s\n", FIRMWARE_VERSION);
  Serial.println("=============================");

  pinMode(LED_BUILTIN, OUTPUT);
  connectWiFi();
}

void loop() {
  if (millis() - lastBlink >= BLINK_MS) {
    digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
    lastBlink = millis();
  }

  if (!firstCheckDone || millis() - lastCheck >= CHECK_INTERVAL_MS) {
    firstCheckDone = true;
    lastCheck = millis();
    checkForUpdate();
  }
}