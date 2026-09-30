"""
vulndb.py
=========
Zafiyet / parmak izi veritabanı (eğitim amaçlı, elle derlenmiş).

Gerçek dünyada bu bilgiler NVD/CVE, CIRCL, ya da üretici bültenlerinden canlı
çekilir. Burada mantığı göstermek için özenle seçilmiş küçük bir küme tutulur.
Her CVE gerçek ve IoT dünyasında bilinen bir örnektir.
"""

# --------------------------------------------------------------------------- #
# 1) Bilinen eski / zafiyetli servis sürümleri
#    bad_below : bu sürümün ALTI "eski" kabul edilir
#    cvss      : ~ CVSS taban puanı (0-10), risk skorlamada ağırlık olarak kullanılır
# --------------------------------------------------------------------------- #
KNOWN_OUTDATED = [
    {"service": "openssh",   "bad_below": "8.0",     "cvss": 7.8, "cve": "CVE-2018-15473",
     "note": "OpenSSH < 8.0 kullanıcı sayımı ve çeşitli zafiyetlere açık."},
    {"service": "dropbear",  "bad_below": "2019.78", "cvss": 8.1, "cve": "CVE-2018-15599",
     "note": "Eski Dropbear SSH: bellek açığa çıkarma / DoS (IoT'de çok yaygın)."},
    {"service": "apache",    "bad_below": "2.4.52",  "cvss": 9.8, "cve": "CVE-2021-41773",
     "note": "Apache httpd path traversal + RCE."},
    {"service": "nginx",     "bad_below": "1.20.1",  "cvss": 7.5, "cve": "CVE-2021-23017",
     "note": "nginx DNS resolver off-by-one, uzaktan çökertme/RCE riski."},
    {"service": "lighttpd",  "bad_below": "1.4.51",  "cvss": 7.5, "cve": "CVE-2018-19052",
     "note": "lighttpd path traversal."},
    {"service": "boa",       "bad_below": "999",     "cvss": 9.8, "cve": "CVE-2017-9833",
     "note": "Boa web server bakımı bırakıldı; IoT kameralarda sık, RCE."},
    {"service": "goahead",   "bad_below": "5.1.5",   "cvss": 9.8, "cve": "CVE-2021-42342",
     "note": "GoAhead web server CGI RCE."},
    {"service": "busybox",   "bad_below": "1.34.0",  "cvss": 8.8, "cve": "CVE-2021-42374",
     "note": "BusyBox çok sayıda CVE (unlzma OOB), IoT firmware'lerinde yaygın."},
    {"service": "vsftpd",    "bad_below": "3.0.3",   "cvss": 10.0, "cve": "CVE-2011-2523",
     "note": "vsftpd 2.3.4 arka kapı (backdoor); eski sürümlerden kaçının."},
    {"service": "mosquitto", "bad_below": "2.0.0",   "cvss": 7.5, "cve": "CVE-2021-34432",
     "note": "Eski Mosquitto MQTT broker DoS / kimlik doğrulama sorunları."},
    {"service": "miniupnpd", "bad_below": "2.1",     "cvss": 9.8, "cve": "CVE-2019-12107",
     "note": "MiniUPnPd bellek bozulması, uzaktan RCE."},
    {"service": "hostapd",   "bad_below": "2.10",    "cvss": 8.1, "cve": "CVE-2021-0326",
     "note": "hostapd/wpa_supplicant P2P bellek zafiyeti."},
]

# --------------------------------------------------------------------------- #
# 2) Üretici OUI önekleri (MAC ilk 3 oktet) -> üretici. IoT ipucu.
# --------------------------------------------------------------------------- #
IOT_OUI_PREFIXES = {
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",    "28:CD:C1": "Raspberry Pi",
    "00:17:88": "Philips Hue (Signify)",   "EC:B5:FA": "Philips Lighting",
    "EC:FA:BC": "Espressif (ESP32)",       "24:0A:C4": "Espressif (ESP32)",
    "5C:CF:7F": "Espressif (ESP8266)",     "A4:CF:12": "Espressif (ESP)",
    "AC:63:BE": "Amazon (Echo/Alexa)",     "44:65:0D": "Amazon Devices",
    "FC:65:DE": "Amazon Devices",          "18:B4:30": "Google Nest",
    "50:C7:BF": "TP-Link (akıllı cihaz)",  "AC:84:C6": "TP-Link",
    "00:7E:56": "Xiaomi IoT",              "78:11:DC": "Xiaomi",
    "64:09:80": "Xiaomi",                  "D0:52:A8": "Samsung SmartThings",
    "28:6C:07": "Samsung",                 "00:1D:C9": "GainSpan (IoT Wi-Fi)",
    "B0:C5:54": "D-Link (kamera/router)",  "00:80:F0": "Panasonic",
    "00:12:FB": "Samsung Electronics",     "00:24:E4": "Withings (sağlık IoT)",
    "18:FE:34": "Espressif",               "68:C6:3A": "Espressif",
    "2C:AA:8E": "Wistron (IoT modül)",     "F0:9F:C2": "Ubiquiti Networks",
}

# --------------------------------------------------------------------------- #
# 3) Yaygın IoT portları -> açıklama
# --------------------------------------------------------------------------- #
COMMON_IOT_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP (web yönetim)", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 554: "RTSP (IP kamera)", 1883: "MQTT", 1900: "SSDP/UPnP",
    2323: "Telnet-alt (Mirai)", 3306: "MySQL", 5000: "UPnP/API",
    5683: "CoAP", 6668: "Tuya IoT", 7547: "TR-069 (CWMP)", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8883: "MQTT/TLS", 9000: "IoT API", 9100: "Yazıcı (JetDirect)",
    49152: "UPnP", 37777: "Dahua DVR", 34567: "XiongMai DVR",
}

# --------------------------------------------------------------------------- #
# 4) Riskli portlar -> (risk ağırlığı, açıklama). Şifresiz/varsayılan-parolalı
#    servisler IoT'de en büyük saldırı yüzeyidir.
# --------------------------------------------------------------------------- #
RISKY_PORTS = {
    23:    (9.0, "Telnet şifresiz — Mirai botnet'in birincil hedefi."),
    2323:  (9.0, "Telnet-alt — Mirai varyantları bu portu tarar."),
    21:    (5.0, "FTP genelde şifresiz; anonim erişim riski."),
    445:   (7.0, "SMB — EternalBlue sınıfı zafiyetler."),
    3306:  (6.0, "MySQL doğrudan ağa açık — varsayılan parola riski."),
    7547:  (7.5, "TR-069 — kitlesel router ele geçirme vektörü."),
    37777: (7.0, "Dahua DVR — bilinen varsayılan kimlik bilgileri."),
    34567: (7.0, "XiongMai DVR — Mirai kaynağı, zayıf kimlik doğrulama."),
    9100:  (4.0, "Ağ yazıcısı — kimlik doğrulamasız baskı/çıkış."),
    1900:  (4.5, "SSDP — DDoS amplifikasyon ve bilgi sızıntısı."),
}

# --------------------------------------------------------------------------- #
# 5) Cihaz tipi parmak izleri. (açık portlar + banner) -> cihaz kategorisi.
#    "any_ports": bu portlardan biri açıksa; "banner": banner'da geçen anahtar.
# --------------------------------------------------------------------------- #
DEVICE_FINGERPRINTS = [
    {"type": "IP Kamera / DVR", "icon": "CAM",
     "any_ports": [554, 37777, 34567], "banner": ["rtsp", "dahua", "hikvision", "dvr", "netcam"]},
    {"type": "Yönlendirici / Router", "icon": "NET",
     "any_ports": [7547, 1900], "banner": ["routeros", "openwrt", "dd-wrt", "tr-069", "miniupnp"]},
    {"type": "Akıllı Ev Hub'ı", "icon": "HUB",
     "any_ports": [1883, 8883, 6668], "banner": ["mosquitto", "mqtt", "tuya", "homeassistant"]},
    {"type": "Ağ Yazıcısı", "icon": "PRN",
     "any_ports": [9100, 631], "banner": ["jetdirect", "cups", "printer"]},
    {"type": "Tek Kart Bilgisayar (Pi vb.)", "icon": "SBC",
     "any_ports": [], "banner": ["raspbian", "debian", "openssh"], "vendor": ["raspberry"]},
    {"type": "Sensör / Mikrodenetleyici", "icon": "SEN",
     "any_ports": [5683], "banner": ["esp", "coap", "arduino"], "vendor": ["espressif"]},
    {"type": "Akıllı Priz / Ampul", "icon": "PLG",
     "any_ports": [6668], "banner": ["tuya", "hue"], "vendor": ["philips", "tp-link"]},
]
