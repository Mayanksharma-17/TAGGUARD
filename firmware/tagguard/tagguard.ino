/*
 * ╔══════════════════════════════════════════════════╗
 * ║  TAGGUARD — ESP32 Firmware v1.0                  ║
 * ║  Tamper-Evident Laboratory Measurement Logger    ║
 * ║  Team: Quad-Coders | CyberHack 2026              ║
 * ╚══════════════════════════════════════════════════╝
 *
 * Board : ESP32 WROOM-32 DevKit V1 (30-pin)
 * IDE   : Arduino IDE 2.x with ESP32 board package
 *
 * Wiring (see circuit diagram):
 *   GPIO34 — Potentiometer wiper via 1k ohm (ADC1)
 *   GPIO18 — Capture button  (INPUT_PULLUP, active LOW)
 *   GPIO19 — LED-test button (INPUT_PULLUP, active LOW)
 *   GPIO25 — Green  LED (READY)    via 330 ohm
 *   GPIO26 — Yellow LED (CAPTURE)  via 330 ohm
 *   GPIO27 — Red    LED (WARNING)  via 330 ohm
 *
 * Serial commands (115200 baud):
 *   KEY <64hex>              Set HMAC-SHA256 key (32 bytes)
 *   KEY?                     Print current key as hex
 *   TIME <ISO8601Z>          Set UTC clock
 *   TIME?                    Print current UTC time
 *   CAPTURE                  Manual capture (same as button)
 *   EXPORT / EXPORT_JSON     Export all records as JSON
 *   EXPORT_CSV               Export all records as CSV
 *   CLEAR                    Delete all stored records
 *   STATUS                   Show system info
 *   HELP                     List commands
 */

#include <Arduino.h>
#include <mbedtls/md.h>
#include <Preferences.h>
#include <time.h>
#include <sys/time.h>

/* ── Pin Definitions ─────────────────────────────── */
#define PIN_POT        34
#define PIN_BTN_CAP    18
#define PIN_BTN_TEST   19
#define PIN_LED_GREEN  25
#define PIN_LED_YELLOW 26
#define PIN_LED_RED    27

/* ── Tunables ────────────────────────────────────── */
#define KEY_SIZE       32
#define MAX_RECORDS    100
#define ADC_SAMPLES    16
#define DEBOUNCE_MS    200
#define VREF           3.3f
#define ADC_MAX        4095.0f
#define SERIAL_BAUD    115200
#define BOOT_WAIT_SEC  5

/* ── Record ──────────────────────────────────────── */
typedef struct {
  int  sequence;
  char source[24];
  char value[16];
  char unit[8];
  char timestamp[32];
  char tag[65];            /* 64 hex + '\0' */
} Record;

/* ── Globals ─────────────────────────────────────── */
Preferences   prefs;
uint8_t       hmacKey[KEY_SIZE];
bool          keyLoaded  = false;
bool          timeReady  = false;
bool          sysReady   = false;

Record        records[MAX_RECORDS];
int           recordCount  = 0;
int           nextSequence = 1;

unsigned long lastCapMs   = 0;
unsigned long lastTestMs  = 0;

/* ── Prototypes ──────────────────────────────────── */
void   handleSerial();
void   processCommand(String cmd);
void   captureReading();
float  readPotVoltage();
void   getCurrentTS(char *buf, size_t len);
void   buildCanonical(const Record *r, char *buf, size_t len);
void   computeHMAC(const char *data, size_t len, char *hexOut);
void   hexEncode(const uint8_t *data, size_t len, char *hexOut);
bool   hexDecode(const char *hex, size_t hexLen, uint8_t *out, size_t outLen);
void   exportJSON();
void   exportCSV();
void   showStatus();
void   showHelp();
void   setAllLEDs(bool on);
void   blinkLED(int pin, int times, int ms);

/* ═══════════════════════════════════════════════════
 *  SETUP
 * ═══════════════════════════════════════════════════ */
void setup() {
  Serial.begin(SERIAL_BAUD);
  while (!Serial) { delay(10); }

  pinMode(PIN_POT,        INPUT);
  pinMode(PIN_BTN_CAP,    INPUT_PULLUP);
  pinMode(PIN_BTN_TEST,   INPUT_PULLUP);
  pinMode(PIN_LED_GREEN,  OUTPUT);
  pinMode(PIN_LED_YELLOW, OUTPUT);
  pinMode(PIN_LED_RED,    OUTPUT);
  setAllLEDs(false);

  /* Load HMAC key from NVS */
  prefs.begin("tagguard", false);
  size_t klen = prefs.getBytes("hmac_key", hmacKey, KEY_SIZE);
  keyLoaded = (klen == KEY_SIZE);

  /* Banner */
  Serial.println();
  Serial.println(F("============================================"));
  Serial.println(F("  TAGGUARD v1.0"));
  Serial.println(F("  Tamper-Evident Measurement Logger"));
  Serial.println(F("  Quad-Coders | CyberHack 2026"));
  Serial.println(F("============================================"));
  Serial.println();

  /* ADC warm-up with LED chase */
  Serial.println(F("[BOOT] ADC stabilization..."));
  for (int i = BOOT_WAIT_SEC; i > 0; i--) {
    Serial.printf("[BOOT] Ready in %d...\r\n", i);
    digitalWrite(PIN_LED_RED,    HIGH); delay(250);
    digitalWrite(PIN_LED_RED,    LOW);
    digitalWrite(PIN_LED_YELLOW, HIGH); delay(250);
    digitalWrite(PIN_LED_YELLOW, LOW);
    digitalWrite(PIN_LED_GREEN,  HIGH); delay(250);
    digitalWrite(PIN_LED_GREEN,  LOW);
    delay(250);
  }
  Serial.println(F("[BOOT] ADC ready."));

  /* Key status */
  if (keyLoaded) {
    Serial.println(F("[BOOT] HMAC key loaded from NVS."));
  } else {
    Serial.println(F("[BOOT] WARNING: No HMAC key.  Send:  KEY <64-hex-chars>"));
    digitalWrite(PIN_LED_RED, HIGH);
  }

  /* Clock status */
  Serial.println(F("[BOOT] WARNING: Clock not set.  Send:  TIME 2026-10-14T09:00:00Z"));
  Serial.println();
  Serial.println(F("Type HELP for commands.  Press CAPTURE button (GPIO18) to record."));
  Serial.println();

  sysReady = true;
  if (keyLoaded) digitalWrite(PIN_LED_GREEN, HIGH);
}

/* ═══════════════════════════════════════════════════
 *  LOOP
 * ═══════════════════════════════════════════════════ */
void loop() {
  handleSerial();

  /* Capture button (active LOW) */
  if (digitalRead(PIN_BTN_CAP) == LOW && millis() - lastCapMs > DEBOUNCE_MS) {
    lastCapMs = millis();
    captureReading();
  }

  /* LED-test button (active LOW) */
  if (digitalRead(PIN_BTN_TEST) == LOW && millis() - lastTestMs > DEBOUNCE_MS) {
    lastTestMs = millis();
    Serial.println(F("[LED TEST] All LEDs on for 1 s"));
    setAllLEDs(true);
    delay(1000);
    setAllLEDs(false);
    if (keyLoaded) digitalWrite(PIN_LED_GREEN, HIGH);
    else           digitalWrite(PIN_LED_RED,   HIGH);
  }

  delay(10);
}

/* ═══════════════════════════════════════════════════
 *  SERIAL COMMAND DISPATCHER
 * ═══════════════════════════════════════════════════ */
void handleSerial() {
  if (!Serial.available()) return;
  String cmd = Serial.readStringUntil('\n');
  cmd.trim();
  if (cmd.length() > 0) processCommand(cmd);
}

void processCommand(String cmd) {
  String u = cmd;
  u.toUpperCase();

  /* ── KEY <hex> ─────────────────────────────────── */
  if (u.startsWith("KEY ")) {
    String h = cmd.substring(4);
    h.trim();
    if (h.length() != 64) {
      Serial.println(F("[ERROR] Key must be 64 hex chars (32 bytes)."));
      return;
    }
    if (!hexDecode(h.c_str(), 64, hmacKey, KEY_SIZE)) {
      Serial.println(F("[ERROR] Invalid hex."));
      return;
    }
    prefs.putBytes("hmac_key", hmacKey, KEY_SIZE);
    keyLoaded = true;
    Serial.println(F("[KEY] HMAC key saved."));
    digitalWrite(PIN_LED_RED, LOW);
    digitalWrite(PIN_LED_GREEN, HIGH);
    return;
  }

  /* ── KEY? ──────────────────────────────────────── */
  if (u == "KEY?") {
    if (!keyLoaded) { Serial.println(F("[KEY] No key loaded.")); return; }
    char hex[65];
    hexEncode(hmacKey, KEY_SIZE, hex);
    Serial.printf("[KEY] %s\r\n", hex);
    return;
  }

  /* ── TIME <ISO8601Z> ───────────────────────────── */
  if (u.startsWith("TIME ")) {
    String ts = cmd.substring(5);
    ts.trim();
    struct tm t;
    memset(&t, 0, sizeof(t));
    if (sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%dZ",
               &t.tm_year, &t.tm_mon, &t.tm_mday,
               &t.tm_hour, &t.tm_min, &t.tm_sec) != 6) {
      Serial.println(F("[ERROR] Use: TIME YYYY-MM-DDTHH:MM:SSZ"));
      return;
    }
    t.tm_year -= 1900;
    t.tm_mon  -= 1;
    time_t epoch = mktime(&t);
    struct timeval tv = { .tv_sec = epoch, .tv_usec = 0 };
    settimeofday(&tv, NULL);
    timeReady = true;
    char buf[32];
    getCurrentTS(buf, sizeof(buf));
    Serial.printf("[TIME] Clock set: %s\r\n", buf);
    return;
  }

  /* ── TIME? ─────────────────────────────────────── */
  if (u == "TIME?") {
    char buf[32];
    getCurrentTS(buf, sizeof(buf));
    Serial.printf("[TIME] %s\r\n", buf);
    return;
  }

  if (u == "CAPTURE")                          { captureReading(); return; }
  if (u == "EXPORT" || u == "EXPORT_JSON")     { exportJSON();     return; }
  if (u == "EXPORT_CSV")                       { exportCSV();      return; }

  if (u == "CLEAR") {
    recordCount = 0;
    nextSequence = 1;
    Serial.println(F("[CLEAR] All records deleted."));
    return;
  }

  if (u == "STATUS") { showStatus(); return; }
  if (u == "HELP")   { showHelp();   return; }

  Serial.printf("[ERROR] Unknown command: %s  (type HELP)\r\n", cmd.c_str());
}

/* ═══════════════════════════════════════════════════
 *  CAPTURE
 * ═══════════════════════════════════════════════════ */
void captureReading() {
  if (!keyLoaded) {
    Serial.println(F("[ERROR] No HMAC key.  Send: KEY <64hex>"));
    blinkLED(PIN_LED_RED, 3, 150);
    return;
  }
  if (!timeReady) {
    Serial.println(F("[ERROR] Clock not set.  Send: TIME <ISO8601Z>"));
    blinkLED(PIN_LED_RED, 3, 150);
    return;
  }
  if (recordCount >= MAX_RECORDS) {
    Serial.println(F("[ERROR] Storage full.  EXPORT then CLEAR."));
    blinkLED(PIN_LED_RED, 5, 100);
    return;
  }

  /* Visual feedback: yellow on */
  digitalWrite(PIN_LED_GREEN,  LOW);
  digitalWrite(PIN_LED_YELLOW, HIGH);

  float voltage = readPotVoltage();

  Record *r = &records[recordCount];
  r->sequence = nextSequence;
  strncpy(r->source, "POT_SENSOR", sizeof(r->source));
  snprintf(r->value,  sizeof(r->value), "%.3f", voltage);
  strncpy(r->unit,   "V",          sizeof(r->unit));
  getCurrentTS(r->timestamp, sizeof(r->timestamp));

  /* Canonical JSON → HMAC-SHA256 → hex tag */
  char canonical[256];
  buildCanonical(r, canonical, sizeof(canonical));
  computeHMAC(canonical, strlen(canonical), r->tag);

  recordCount++;
  nextSequence++;

  Serial.printf("[CAPTURE] #%03d | %s | %s %s | %s | tag: %.16s...\r\n",
                r->sequence, r->source, r->value, r->unit,
                r->timestamp, r->tag);

  delay(300);
  digitalWrite(PIN_LED_YELLOW, LOW);
  digitalWrite(PIN_LED_GREEN,  HIGH);
}

/* ═══════════════════════════════════════════════════
 *  SENSOR
 * ═══════════════════════════════════════════════════ */
float readPotVoltage() {
  long sum = 0;
  for (int i = 0; i < ADC_SAMPLES; i++) {
    sum += analogRead(PIN_POT);
    delayMicroseconds(500);
  }
  return ((float)sum / ADC_SAMPLES) * VREF / ADC_MAX;
}

/* ═══════════════════════════════════════════════════
 *  TIMESTAMP
 * ═══════════════════════════════════════════════════ */
void getCurrentTS(char *buf, size_t len) {
  time_t now;
  time(&now);
  struct tm *g = gmtime(&now);
  snprintf(buf, len, "%04d-%02d-%02dT%02d:%02d:%02dZ",
           g->tm_year + 1900, g->tm_mon + 1, g->tm_mday,
           g->tm_hour, g->tm_min, g->tm_sec);
}

/* ═══════════════════════════════════════════════════
 *  CANONICAL JSON  (must match Python verifier)
 *
 *  Sorted keys: sequence, source, timestamp, unit, value
 *  Compact separators, no whitespace, UTF-8.
 * ═══════════════════════════════════════════════════ */
void buildCanonical(const Record *r, char *buf, size_t len) {
  snprintf(buf, len,
    "{\"sequence\":%d,"
    "\"source\":\"%s\","
    "\"timestamp\":\"%s\","
    "\"unit\":\"%s\","
    "\"value\":\"%s\"}",
    r->sequence, r->source, r->timestamp, r->unit, r->value);
}

/* ═══════════════════════════════════════════════════
 *  HMAC-SHA256  (mbedTLS, built into ESP32 core)
 * ═══════════════════════════════════════════════════ */
void computeHMAC(const char *data, size_t dataLen, char *hexOut) {
  uint8_t hash[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx,
                   mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, hmacKey, KEY_SIZE);
  mbedtls_md_hmac_update(&ctx, (const uint8_t *)data, dataLen);
  mbedtls_md_hmac_finish(&ctx, hash);
  mbedtls_md_free(&ctx);
  hexEncode(hash, 32, hexOut);
}

/* ═══════════════════════════════════════════════════
 *  HEX HELPERS
 * ═══════════════════════════════════════════════════ */
void hexEncode(const uint8_t *data, size_t len, char *hexOut) {
  for (size_t i = 0; i < len; i++)
    sprintf(hexOut + i * 2, "%02x", data[i]);
  hexOut[len * 2] = '\0';
}

bool hexDecode(const char *hex, size_t hexLen,
               uint8_t *out, size_t outLen) {
  if (hexLen != outLen * 2) return false;
  for (size_t i = 0; i < outLen; i++) {
    char pair[3] = { hex[i*2], hex[i*2+1], '\0' };
    char *end;
    long v = strtol(pair, &end, 16);
    if (*end != '\0') return false;
    out[i] = (uint8_t)v;
  }
  return true;
}

/* ═══════════════════════════════════════════════════
 *  EXPORT — JSON
 * ═══════════════════════════════════════════════════ */
void exportJSON() {
  if (recordCount == 0) {
    Serial.println(F("[EXPORT] No records."));
    return;
  }
  Serial.println(F("--- BEGIN JSON ---"));
  Serial.println("[");
  for (int i = 0; i < recordCount; i++) {
    Record *r = &records[i];
    Serial.println("  {");
    Serial.printf("    \"sequence\": %d,\r\n",      r->sequence);
    Serial.printf("    \"source\": \"%s\",\r\n",    r->source);
    Serial.printf("    \"value\": \"%s\",\r\n",     r->value);
    Serial.printf("    \"unit\": \"%s\",\r\n",      r->unit);
    Serial.printf("    \"timestamp\": \"%s\",\r\n", r->timestamp);
    Serial.printf("    \"tag\": \"%s\"\r\n",        r->tag);
    Serial.printf("  }%s\r\n", i < recordCount - 1 ? "," : "");
  }
  Serial.println("]");
  Serial.println(F("--- END JSON ---"));
  Serial.printf("[EXPORT] %d record(s) as JSON.\r\n", recordCount);
}

/* ═══════════════════════════════════════════════════
 *  EXPORT — CSV
 * ═══════════════════════════════════════════════════ */
void exportCSV() {
  if (recordCount == 0) {
    Serial.println(F("[EXPORT] No records."));
    return;
  }
  Serial.println(F("--- BEGIN CSV ---"));
  Serial.println(F("sequence,source,value,unit,timestamp,tag"));
  for (int i = 0; i < recordCount; i++) {
    Record *r = &records[i];
    Serial.printf("%d,%s,%s,%s,%s,%s\r\n",
      r->sequence, r->source, r->value, r->unit,
      r->timestamp, r->tag);
  }
  Serial.println(F("--- END CSV ---"));
  Serial.printf("[EXPORT] %d record(s) as CSV.\r\n", recordCount);
}

/* ═══════════════════════════════════════════════════
 *  STATUS / HELP
 * ═══════════════════════════════════════════════════ */
void showStatus() {
  Serial.println(F("========== STATUS =========="));
  Serial.printf("  HMAC Key : %s\r\n", keyLoaded ? "Loaded" : "NOT SET");
  Serial.printf("  Clock    : %s\r\n", timeReady ? "Set"    : "NOT SET");
  Serial.printf("  Records  : %d / %d\r\n", recordCount, MAX_RECORDS);
  Serial.printf("  Next Seq : %d\r\n", nextSequence);
  if (timeReady) {
    char buf[32];
    getCurrentTS(buf, sizeof(buf));
    Serial.printf("  UTC Now  : %s\r\n", buf);
  }
  Serial.printf("  Pot Read : %.3f V\r\n", readPotVoltage());
  Serial.println(F("============================"));
}

void showHelp() {
  Serial.println(F("========== COMMANDS =========="));
  Serial.println(F("  KEY <hex64>    Set 32-byte HMAC key"));
  Serial.println(F("  KEY?           Show current key"));
  Serial.println(F("  TIME <iso>     Set UTC clock  e.g. 2026-10-14T09:00:00Z"));
  Serial.println(F("  TIME?          Show current UTC time"));
  Serial.println(F("  CAPTURE        Record a measurement"));
  Serial.println(F("  EXPORT         Export records (JSON)"));
  Serial.println(F("  EXPORT_CSV     Export records (CSV)"));
  Serial.println(F("  CLEAR          Delete all records"));
  Serial.println(F("  STATUS         System info"));
  Serial.println(F("  HELP           This list"));
  Serial.println(F("=============================="));
}

/* ═══════════════════════════════════════════════════
 *  LED HELPERS
 * ═══════════════════════════════════════════════════ */
void setAllLEDs(bool on) {
  uint8_t v = on ? HIGH : LOW;
  digitalWrite(PIN_LED_GREEN,  v);
  digitalWrite(PIN_LED_YELLOW, v);
  digitalWrite(PIN_LED_RED,    v);
}

void blinkLED(int pin, int times, int ms) {
  for (int i = 0; i < times; i++) {
    digitalWrite(pin, HIGH); delay(ms);
    digitalWrite(pin, LOW);  delay(ms);
  }
  if (keyLoaded) digitalWrite(PIN_LED_GREEN, HIGH);
}
