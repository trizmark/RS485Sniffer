//#include "ESPAsyncTCP.h"
#include <Arduino.h>

// work around SPIFFS deprecation
// redefine it to be LitteFS
#include <FS.h>
#define SPIFFS LittleFS
#include <LittleFS.h> 

//#include <ESP8266WiFi.h>
//#include <ESP8266mDNS.h>    // included with ESP8266 board def install
#include <ESPmDNS.h>
#include <WiFiUdp.h>

#include <ESPAsyncWiFiManager.h>

#include <ArduinoOTA.h>
String hostName = "rs485sniffer-2";

// network related objects
WiFiUDP udp;
AsyncWebServer server(80);
WiFiClient espClient;
DNSServer dns;

// Modbus RTU framing configuration.
constexpr uint32_t MODBUS_BAUD_RATE = 9600;
constexpr uint32_t MODBUS_CHARACTER_BITS = 10; // 8N1: start + 8 data + stop
constexpr uint32_t MODBUS_T3_5_MICROS =
    (3500000UL * MODBUS_CHARACTER_BITS + MODBUS_BAUD_RATE - 1) /
    MODBUS_BAUD_RATE;

// Increase this value if the maximum frame size changes.
constexpr size_t MAX_MODBUS_FRAME_SIZE = 64;
constexpr uint16_t UDP_DESTINATION_PORT = 9999;

uint8_t candidateBuffer[MAX_MODBUS_FRAME_SIZE];
size_t candidateLength = 0;
uint32_t lastByteMicros = 0;

IPAddress remote_ip(192, 168, 0, 201);

//#define RX_PIN D5
//#define TX_PIN D6
#define RX_PIN 16
#define TX_PIN 17

//EspSoftwareSerial::UART Serial2;
//HardwareSerial Serial2(2);

/*
 *  Initialise OTA
 */
void init_OTA() {
    Serial.println("[OTA  ] Setting up OTA");

    ArduinoOTA.onStart([]() {
        String type;
        if (ArduinoOTA.getCommand() == U_FLASH)
            type = "program";
        else // U_FS
            type = "filesystem";

        // NOTE: if updating FS this would be the place to unmount FS using FS.end()
        SPIFFS.end();
        Serial.println("[OTA  ] Start updating " + type);
    });

    ArduinoOTA.onEnd([]() {
        Serial.println("[OTA  ] Update finished");
    });

    ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
        char buf[32];
        sprintf(buf, "[OTA  ] Progress: %u%%\r", (progress / (total / 100)));
        Serial.println(buf);
    });

    ArduinoOTA.onError([](ota_error_t error) {
        char buf[32];
        sprintf(buf, "[OTA  ] Error[%u]: ", error);
        Serial.println(buf);
        if (error == OTA_AUTH_ERROR)
            Serial.println("Auth Failed");
        else if (error == OTA_BEGIN_ERROR)
            Serial.println("Begin Failed");
        else if (error == OTA_CONNECT_ERROR)
            Serial.println("Connect Failed");
        else if (error == OTA_RECEIVE_ERROR)
            Serial.println("Receive Failed");
        else if (error == OTA_END_ERROR)
            Serial.println("End Failed");
    });

    // start OTA receiver with mDNS
    ArduinoOTA.setHostname(hostName.c_str());
    //ArduinoOTA.begin(true);
    ArduinoOTA.begin();

    Serial.println("[OTA  ] OTA setup complete");
}

/*
 *  Initialise WiFi (via WifiManager)
 */
void init_WiFi() {
    // start WiFi auto configuration
    WiFi.persistent(true); 
    AsyncWiFiManager wifiManager(&server, &dns);;
    wifiManager.autoConnect("RS485Sniffer_AutoConfig");
    Serial.println("[WiFi ] WiFi setup complete");
}

/*
 *  Register on mDNS
 */
void init_mDNS() {
    // mDNS already set up by ArduinoOTA
    // all we need to do is advertise the HTTP server
    MDNS.addService("http", "tcp", 80);
    Serial.println("[MDNS ] mDNS setup complete");
}

void setup() {
  // init the serial port
  Serial.begin(115200);

  Serial.println("[SETUP] Setup starting");

  // init various items
  init_WiFi();
  init_OTA();
  init_mDNS();

  //Serial2.begin(MODBUS_BAUD_RATE, SWSERIAL_8N1, RX_PIN, TX_PIN, false);
  //Serial2.begin(MODBUS_BAUD_RATE, SERIAL_8N1, 16, 17, false);
  Serial2.begin(MODBUS_BAUD_RATE, SERIAL_8N1, RX_PIN, TX_PIN);

  Serial.println("[SETUP] Setup complete");
}


void p(int X) {
  if (X < 16) {Serial.print("0"); }
  Serial.print(X, HEX);
}

bool isSupportedFunction(uint8_t functionCode) {
  const uint8_t baseFunction = functionCode & 0x7F;
  return baseFunction == 0x03 || baseFunction == 0x04 ||
         baseFunction == 0x06 || baseFunction == 0x10;
}

bool crcIsValid(size_t frameLength) {
  if (frameLength < 4 || frameLength > candidateLength) {
    return false;
  }

  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < frameLength - 2; ++i) {
    crc ^= candidateBuffer[i];
    for (uint8_t bit = 0; bit < 8; ++bit) {
      if (crc & 0x0001) {
        crc = (crc >> 1) ^ 0xA001;
      } else {
        crc >>= 1;
      }
    }
  }

  const uint16_t receivedCrc =
      static_cast<uint16_t>(candidateBuffer[frameLength - 2]) |
      (static_cast<uint16_t>(candidateBuffer[frameLength - 1]) << 8);
  return crc == receivedCrc;
}

void discardCandidate() {
  candidateLength = 0;
}

void sendCandidate() {
  Serial.println();

  udp.beginPacket(remote_ip, UDP_DESTINATION_PORT);
  udp.write(candidateBuffer, candidateLength);
  udp.endPacket();

  discardCandidate();
}

bool tryCandidateLength(size_t frameLength) {
  if (frameLength > MAX_MODBUS_FRAME_SIZE || candidateLength < frameLength) {
    return false;
  }

  if (!crcIsValid(frameLength)) {
    return false;
  }

  // A valid candidate must consume the complete receive buffer. This prevents
  // accepting a shorter valid prefix and treating the remaining bytes as lost.
  if (frameLength != candidateLength) {
    return false;
  }

  sendCandidate();
  return true;
}

bool tryCompleteCandidate() {
  if (candidateLength < 2 || !isSupportedFunction(candidateBuffer[1])) {
    return false;
  }

  const uint8_t functionCode = candidateBuffer[1];
  const uint8_t baseFunction = functionCode & 0x7F;

  // Exception responses contain address, exception function, exception code,
  // and CRC. They are valid responses for the supported base functions.
  if ((functionCode & 0x80) != 0) {
    return tryCandidateLength(5);
  }

  if (baseFunction == 0x03 || baseFunction == 0x04) {
    // A read response's byte count disambiguates it from an 8-byte request.
    // Check the response candidate first when it is complete, then check the
    // fixed request candidate. This also works when several frames are
    // already buffered by the serial driver and their physical gaps are no
    // longer observable by the application.
    if (candidateLength >= 3) {
      const uint8_t byteCount = candidateBuffer[2];
      if (byteCount != 0 && (byteCount % 2) == 0) {
        const size_t responseLength = static_cast<size_t>(5) + byteCount;
        if (responseLength <= candidateLength &&
            tryCandidateLength(responseLength)) {
          return true;
        }
      }
    }

    // Request: address, function, start address, quantity, CRC.
    return tryCandidateLength(8);
  }

  if (baseFunction == 0x06) {
    // Read/write single register request and response are both fixed length.
    return tryCandidateLength(8);
  }

  // Function 0x10 request and response lengths overlap at eight bytes. Prefer
  // a structurally complete variable request when its length is available.
  if (candidateLength >= 7) {
    const uint16_t quantity =
        (static_cast<uint16_t>(candidateBuffer[4]) << 8) |
        candidateBuffer[5];
    const uint8_t byteCount = candidateBuffer[6];
    if (quantity >= 1 && quantity <= 123 && byteCount != 0 &&
        byteCount == quantity * 2) {
      return tryCandidateLength(static_cast<size_t>(9) + byteCount);
    }
  }

  // Function 0x10 response: address, function, start address, quantity, CRC.
  return tryCandidateLength(8);
}

bool tryGapCandidate() {
  if (candidateLength != 8 || candidateLength < 2 ||
      !isSupportedFunction(candidateBuffer[1])) {
    return false;
  }

  const uint8_t baseFunction = candidateBuffer[1] & 0x7F;
  if (baseFunction == 0x03 || baseFunction == 0x04 ||
      baseFunction == 0x10) {
    return tryCandidateLength(8);
  }
  return false;
}

void receiveModbusByte(uint8_t value) {
  const uint32_t now = micros();

  // A gap ends an ambiguous eight-byte request candidate. Longer or invalid
  // candidates are discarded before the new byte starts the next frame.
  if (candidateLength > 0 &&
      static_cast<uint32_t>(now - lastByteMicros) >= MODBUS_T3_5_MICROS) {
    if (!tryGapCandidate()) {
      discardCandidate();
    }
  }

  if (candidateLength >= MAX_MODBUS_FRAME_SIZE) {
    discardCandidate();
  }

  candidateBuffer[candidateLength++] = value;
  lastByteMicros = now;
  p(value);
  tryCompleteCandidate();
}

void loop() {
  // Handle mDNS and OTA.
  ArduinoOTA.handle();

  // Drain the software serial buffer. Candidate lengths and CRC determine
  // normal frame completion; the RTU gap is retained for recovery only.
  while (Serial2.available() > 0) {
    const int received = Serial2.read();
    if (received >= 0) {
      receiveModbusByte(static_cast<uint8_t>(received));
    }
  }

  // Finalize a lone eight-byte request after the RTU inter-frame gap.
  if (candidateLength > 0 &&
      static_cast<uint32_t>(micros() - lastByteMicros) >= MODBUS_T3_5_MICROS) {
    if (!tryGapCandidate()) {
      discardCandidate();
    }
  }
}
