/* ------------------------------------------------- */
/* esp32-wifisniffer-tft.ino          20191228 fm4dd */
/*                                                   */
/* ESP32 Wifi AP Sniffer for 2.4Ghz Band, displayed  */
/* on a 320x240 WaveShare TFT in portait orientation */
/* Inspired by 36C3 Wifi Fox Hunt MysteryHack space. */
/* https://github.com/fm4dd/esp32-wifisniffer-tft    */
/*                                                   */
/* Code fragments incl. snippets from various repos  */
/* eg https://github.com/ESP-EOS/ESP32-WiFi-Sniffer  */
/* & https://github.com/michelep/ESP32_BeaconSniffer */
/* Thanks Łukasz Podkalicki Michele "O-Zone" +others */
/* ------------------------------------------------- */
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "SPI.h"
#include "tft.h"

#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
// WiFi 802.11 2.4 GHz ISM band: 14 channels, 1-13 used
#define WIFI_CHANNEL_MAX               (13)

#define DISPLAY_MAX_W 240
#define DISPLAY_MAX_H 320
#define TFT_CS        5   // do not use GPI032 or GPIO33 here
#define TFT_DC        17  // do not use GPI032 or GPIO33 here
#define SPI_MOSI      23  // ESP32 HW-SPI MOSI
#define SPI_MISO      19  // ESP32 HW-SPI MISO
#define SPI_SCK       18  // ESP32 HW-SPI Clock 
#define TP_IRQ        39  // TFT touch controller INT
#define TP_CS         4   // TFT touch controller select
#define SD_CS         16  // TFT SD card reader select
#define LED1          32  // output LED 1
#define LED2          33  // output LED 2

#define min(X, Y) (((X) < (Y)) ? (X) : (Y))
TFT tft(1);               // 0=ILI9341, 1= HX8347D
char lineStr[255];
uint8_t level = 0, channel = 1;
#define APLIMIT 24
uint8_t show_ap;     // list of AP to display

static wifi_country_t wifi_country = {.cc="DE", .schan = 1, .nchan = 13}; //Most recent esp32 library struct

typedef struct {
  unsigned protocol:2;
  unsigned type:2;
  unsigned subtype:4;
  unsigned to_ds:1;
  unsigned from_ds:1;
  unsigned more_frag:1;
  unsigned retry:1;
  unsigned pwr_mgmt:1;
  unsigned more_data:1;
  unsigned wep:1;
  unsigned strict:1;
} wifi_header_frame_control_t;

typedef struct {
  wifi_header_frame_control_t frame_ctrl;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

typedef struct {
  unsigned interval:16;
  unsigned capability:16;
  unsigned tag_number:8;
  unsigned tag_length:8;
  char ssid[0];
  uint8_t rates[1];
} wifi_beacon_hdr;

typedef struct {
  uint8_t mac[6];
} __attribute__((packed)) mac_addr;


typedef enum {
  ASSOCIATION_REQ,
  ASSOCIATION_RES,
  REASSOCIATION_REQ,
  REASSOCIATION_RES,
  PROBE_REQ,
  PROBE_RES,
  NU1,  /* ......................*/
  NU2,  /* 0110, 0111 not used */
  BEACON,
  ATIM,
  DISASSOCIATION,
  AUTHENTICATION,
  DEAUTHENTICATION,
  ACTION,
  ACTION_NACK,
} wifi_mgmt_subtypes_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event){
  return ESP_OK;
}

void wifi_sniffer_init(void){
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_set_channel(uint8_t channel){
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type){
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type){
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  char ssid[32] = {0};
  const wifi_header_frame_control_t *fctl = (wifi_header_frame_control_t *)&hdr->frame_ctrl;
  
  // Details about beacon frames: https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/
  if(fctl->subtype == BEACON) { //beacon
    wifi_beacon_hdr *beacon=(wifi_beacon_hdr*)ipkt->payload;

    if(beacon->tag_length >= 32) strncpy(ssid, beacon->ssid, 31);
    else strncpy(ssid, beacon->ssid, beacon->tag_length);
  
    Serial.printf("Beacon %s\n",ssid);
    addBeacon(ssid, ppkt->rx_ctrl.channel, ppkt->rx_ctrl.rssi);
  }

  printf("PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
    " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
    " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
    " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
    wifi_sniffer_packet_type2str(type),
    ppkt->rx_ctrl.channel,
    ppkt->rx_ctrl.rssi,
    /* ADDR1 */
    hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
    hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
    /* ADDR2 */
    hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
    hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
    /* ADDR3 */
    hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
    hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
  );
}

#include <LinkedList.h>

class WiFiBeacon {
  public:
    char name[32];
    int rssi;
    uint8_t channel;
    char mac[6]; 
    uint8_t lastseen;
};

LinkedList<WiFiBeacon*> myBeacons = LinkedList<WiFiBeacon*>();

void addBeacon(char ssid[],uint8_t channel, int rssi) {
  WiFiBeacon *beacon;
  for(int i = 0; i < myBeacons.size(); i++) {
    beacon = myBeacons.get(i); 
    if(strncmp(beacon->name,ssid,32)==0) {
      // update beacon data and return
      beacon->rssi = rssi;
      beacon->channel = channel;
      beacon->lastseen = 0;
      Serial.printf("Update beacon %s\n",ssid);
      return;
    }
  }
  // add new beacon  
  beacon = new WiFiBeacon();
  strncpy(beacon->name,ssid,32);
  beacon->channel = channel;
  beacon->rssi = rssi;
  beacon->lastseen = 0;
  myBeacons.add(beacon);
  Serial.printf("Add new beacon %s on channel %d\n",ssid,channel);
}

hw_timer_t *timer = NULL;
bool timerChannel=false;
void IRAM_ATTR onTimer(){ timerChannel=true; }

void setup() {
  Serial.begin(115200);
  //SPI.begin(SPI_SCK, SPI_MISO, SPI_MOSI);
  tft.begin(TFT_CS, TFT_DC, SPI_MOSI, SPI_MISO, SPI_SCK);
  tft.setFrequency(60000000); // 60MHz max for WaveShare TFT
  tft.setRotation(2);
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE);
  tft.setCursor(0, 0);
  tft.setFont(Garamond34x42);
  String line1 = "36C3";
  tft.println(line1);

  wifi_sniffer_init();
  pinMode(LED1, OUTPUT);
  timer = timerBegin(0, 80, true);
  timerAttachInterrupt(timer, &onTimer, true);
  timerAlarmWrite(timer, 1000000, true);
  timerAlarmEnable(timer);
  delay(3000);
  // clear the display
  tft.fillRect(0, 0, (DISPLAY_MAX_W-1), (DISPLAY_MAX_H-1), TFT_BLACK);
  // horizontal lines over the display
  tft.drawFastHLine(0, 0, DISPLAY_MAX_W, TFT_GREEN);
  tft.drawFastVLine((DISPLAY_MAX_W-1), 1, 4, TFT_GREEN);
  tft.drawFastHLine(0, 5, DISPLAY_MAX_W, TFT_GREEN);
  tft.drawFastHLine(0, 20, DISPLAY_MAX_W, TFT_GREEN);
  tft.drawFastHLine(0, 21, DISPLAY_MAX_W, TFT_GREEN);
  tft.drawFastHLine(0, 22, DISPLAY_MAX_W, TFT_GREEN);
  tft.setTextColor(TFT_WHITE);
  tft.setFont(Times_New_Roman15x14);
}

void loop() {
  if(timerChannel) {
    WiFiBeacon *beacon;
        
    // Age for all beacons detected...
    for(int i = 0; i < myBeacons.size(); i++) {
      beacon = myBeacons.get(i); 
      beacon->lastseen++;
      if(beacon->lastseen > 60) {
        // older that 60 secs? remove it!
        Serial.printf("Remove lost beacon %s\n",beacon->name);
        myBeacons.remove(i);
      }
    }
    // Set channel
    wifi_sniffer_set_channel(channel);
    channel = (channel % WIFI_CHANNEL_MAX) + 1;

    // channel scan progress bar
    tft.fillRect(0,1,(DISPLAY_MAX_W-2), 4, TFT_BLACK);
    tft.fillRect(0,1, round((DISPLAY_MAX_W / WIFI_CHANNEL_MAX)*channel), 4, TFT_WHITE);

    // channnel number and count of APs found
    tft.fillRect(0,6,DISPLAY_MAX_W, 11, TFT_BLACK);
    tft.setCursor(0, 6);
    tft.println("SCAN WIFI CHANNEL: "+String(channel));
    tft.setCursor(150, 6);
    tft.println("TOTAL AP: "+String(myBeacons.size()));

    // Display the list of nearest APs, up to aplimit
    if (myBeacons.size() < APLIMIT) show_ap = myBeacons.size();
    for(int i=0; i<show_ap; i++) {
      beacon = myBeacons.get(i);
      tft.fillRect(0,24+(12*i),DISPLAY_MAX_W, 12, TFT_BLACK);
      tft.setCursor(0,24+(12*i));
      sprintf(lineStr, "%02d %02d [", i, beacon->channel);
      tft.print(lineStr);
      if (beacon->rssi > -55) {
        tft.setTextColor(TFT_WHITE);  // strongest
      } else if (beacon->rssi < -55 & beacon->rssi > -65) {
        tft.setTextColor(TFT_GREEN);  // strong
      } else if (beacon->rssi < -65 & beacon->rssi > -70) {
        tft.setTextColor(TFT_GREENYELLOW); // medium
      } else if (beacon->rssi < -70 & beacon->rssi > -78) {
        tft.setTextColor(TFT_YELLOW); // low medium
      } else if (beacon->rssi < -78 & beacon->rssi > -82) {
        tft.setTextColor(TFT_ORANGE);    // weaker
      } else {
        tft.setTextColor(TFT_RED);   // weakest
      }
      tft.print(String(beacon->rssi));
      tft.setTextColor(TFT_WHITE);
      tft.print("] "+String(beacon->name));
      // delete space below in case the list shrinks
      if(36+(12*i) < DISPLAY_MAX_H) {
        tft.fillRect(0,36+(12*i),DISPLAY_MAX_W, (12*i), TFT_BLACK);
      }
    }
    timerChannel=false;
  }
  vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
  if (digitalRead(LED1) == LOW) digitalWrite(LED1, HIGH);
  else digitalWrite(LED1, LOW);
}
