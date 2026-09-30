"""
signatures.py
-------------
Bilinen "eski / zafiyetli" servis sürümlerini tutan basit imza veritabanı.

Bu dosya EĞİTİM amaçlıdır. Gerçek bir zafiyet yönetimi aracı (ör. OpenVAS,
Nessus) çevrimiçi CVE/NVD veritabanlarını kullanır. Burada, ödevde mantığı
göstermek için elle derlenmiş küçük bir küme tutuyoruz.

Her kayıt:
  - service : servis adı (banner'dan tespit edilen, küçük harf)
  - bad_below : bu sürümün ALTINDAKİ her şey "eski" kabul edilir (güvenli asgari)
  - note : neden riskli olduğuna dair kısa not / örnek CVE
"""

# IoT cihazlarında sık görülen servisler ve "güvenli asgari sürüm" eşikleri.
# Sürümler örnektir; raporunda kaynak (CVE/NVD) göstererek güncelleyebilirsin.
KNOWN_OUTDATED = [
    {
        "service": "openssh",
        "bad_below": "8.0",
        "note": "OpenSSH < 8.0 birçok bilinen zafiyet içerir (ör. CVE-2018-15473 kullanıcı sayımı).",
    },
    {
        "service": "dropbear",
        "bad_below": "2019.78",
        "note": "Eski Dropbear SSH sürümleri IoT'de yaygın; format string / DoS sorunları.",
    },
    {
        "service": "lighttpd",
        "bad_below": "1.4.51",
        "note": "Eski lighttpd sürümlerinde path traversal / DoS zafiyetleri.",
    },
    {
        "service": "apache",
        "bad_below": "2.4.52",
        "note": "Apache httpd < 2.4.52 çeşitli RCE/path traversal zafiyetleri (ör. CVE-2021-41773).",
    },
    {
        "service": "nginx",
        "bad_below": "1.20.1",
        "note": "Eski nginx sürümlerinde DNS resolver / HTTP/2 zafiyetleri.",
    },
    {
        "service": "boa",
        "bad_below": "999",  # Boa web server geliştirmesi durdu; her sürüm riskli.
        "note": "Boa web server bakımı bırakıldı; IoT'de sık ve zafiyetli (CVE-2017-9833 vb.).",
    },
    {
        "service": "goahead",
        "bad_below": "5.1.5",
        "note": "GoAhead web server eski sürümlerinde RCE (CVE-2021-42342).",
    },
    {
        "service": "busybox",
        "bad_below": "1.34.0",
        "note": "Eski BusyBox sürümleri çok sayıda CVE barındırır (IoT firmware'lerinde yaygın).",
    },
    {
        "service": "vsftpd",
        "bad_below": "3.0.3",
        "note": "vsftpd 2.3.4 ünlü backdoor; eski sürümlerden kaçının.",
    },
    {
        "service": "mosquitto",
        "bad_below": "2.0.0",
        "note": "Eski Mosquitto (MQTT broker) sürümlerinde kimlik doğrulama/DoS sorunları.",
    },
]

# IoT üreticilerinin MAC adresi OUI (ilk 3 oktet) önekleri.
# Cihazın "IoT olma ihtimalini" tahmin etmek için kaba bir ipucu.
IOT_OUI_PREFIXES = {
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "00:17:88": "Philips Hue (Signify)",
    "EC:FA:BC": "Espressif (ESP32/ESP8266)",
    "24:0A:C4": "Espressif (ESP32/ESP8266)",
    "5C:CF:7F": "Espressif (ESP8266)",
    "AC:63:BE": "Amazon (Echo/Alexa)",
    "44:65:0D": "Amazon Devices",
    "18:B4:30": "Nest Labs",
    "50:C7:BF": "TP-Link (akıllı priz/kamera)",
    "00:7E:56": "Xiaomi IoT",
    "78:11:DC": "Xiaomi",
    "D0:52:A8": "Samsung SmartThings",
    "00:1D:C9": "GainSpan (IoT Wi-Fi)",
}

# IoT'de sık açık olan portlar -> servis/anlam. Fingerprinting için ipucu.
COMMON_IOT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet (RİSKLİ - IoT'de çok yaygın)",
    53: "DNS",
    80: "HTTP (web yönetim arayüzü)",
    443: "HTTPS",
    554: "RTSP (IP kamera)",
    1883: "MQTT (IoT mesajlaşma)",
    5000: "UPnP / API",
    5683: "CoAP (IoT)",
    8080: "HTTP-alt (yönetim arayüzü)",
    8443: "HTTPS-alt",
    8883: "MQTT over TLS",
    9000: "Çeşitli IoT API",
    49152: "UPnP",
}
