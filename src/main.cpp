#include <Arduino.h>

// work around SPIFFS deprecation
// redefine it to be LitteFS
#include <FS.h>
#define SPIFFS LittleFS
#include <LittleFS.h> 

#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>    // included with ESP8266 board def install
#include <WiFiUdp.h>

#include <ESPAsyncWiFiManager.h>

#include <ArduinoOTA.h>
String hostName = "rs485sniffer";

#include "SoftwareSerial.h"


// network related objects
WiFiUDP udp;
AsyncWebServer server(80);
WiFiClient espClient;
DNSServer dns;

// Inter-MODBUS message gap in millis
#define INTERMESSAGE_GAP  5

#define MESSAGE_GAP_TIMEOUT_IN_MICROS   500

unsigned int localPort = 8888;
char RecvBuffer[256];

unsigned int recvIndex = 0;
unsigned long msgIndex = 0;
unsigned long receiveTime = 0;

char receiveTimeString[32];
char msgIndexString[32];

bool dumpData = false;

IPAddress remote_ip(192, 168, 0, 201);

#define RX_PIN D5
#define TX_PIN D6

EspSoftwareSerial::UART myPort;

int received;
unsigned long lastModbusEvent;
bool fReadData = false;


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
    ArduinoOTA.begin(true);

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
}

/*
 *  Register on mDNS
 */
void init_mDNS() {
    // mDNS already set up by ArduinoOTA
    // all we need to do is advertise the HTTP server
    MDNS.addService("http", "tcp", 80);
}

void setup() {
  // init various items
  init_WiFi();
  init_OTA();
  init_mDNS();

  // init the serial port
  Serial.begin(115200);

  myPort.begin(9600, SWSERIAL_8N1, RX_PIN, TX_PIN, false);

  lastModbusEvent = millis();
}


void p(int X) {
  if (X < 16) {Serial.print("0"); }
  Serial.print(X, HEX);
}

void loop() {
  // handle mDNS and OTA
  ArduinoOTA.handle();

  if (myPort.available() > 0) {
    received = myPort.read();
    RecvBuffer[recvIndex++] = received;
    p(received);
    lastModbusEvent = millis();
    fReadData = true;
  }

  // check if we need to send the data
  if (millis() - lastModbusEvent > INTERMESSAGE_GAP && fReadData) {
    Serial.println();
    lastModbusEvent = millis();
    fReadData = false;

    // send the data via UDP
    udp.beginPacket(remote_ip, 8888);
    udp.write(RecvBuffer, recvIndex);
    udp.endPacket();

    // reset index for next message
    recvIndex = 0;
  }

/*
  if (myPort.available() > 0) {
    received = myPort.read();
    //RecvBuffer[recvIndex++] = received;

    //if (recvIndex>32) {
    //  dumpData = true;
    //}
  }
*/
/*
  // If the timer expired and positioned this var, we should now dump the received message
  // into a UDP packet to the remote host/logger.
  if (dumpData) {
    receiveTime = micros() - MESSAGE_GAP_TIMEOUT_IN_MICROS;
    
    // reinitialize vars for next detection/dump
    dumpData = false;

    msgIndex++ ;
    if (msgIndex > 999) msgIndex = 0;
    
    // build and send UDP message
    udp.beginPacket(remote_ip, 8888);
    
    sprintf(receiveTimeString, "%015lu:", receiveTime);
    udp.write(receiveTimeString, strlen(receiveTimeString));

    sprintf(msgIndexString, "%04lu:", msgIndex);
    udp.write(msgIndexString, strlen(msgIndexString));
    
    udp.write(RecvBuffer, recvIndex);

    udp.endPacket();

    // reset index for next message
    recvIndex = 0;
  }
*/
}

