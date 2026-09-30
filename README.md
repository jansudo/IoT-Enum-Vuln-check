# IoT Güvenlik Tarayıcısı — Web Kontrol Paneli

Yerel ağdaki **IoT cihazlarını tespit eden**, **portlarını tarayan**, çalışan
servislerin **eski / zafiyetli sürüm** barındırıp barındırmadığını kontrol eden ve
her cihaz için **risk skoru** üreten, canlı web arayüzlü bir güvenlik aracı.

Bilgi Güvenliği dersi için — **savunma / eğitim amaçlı**.

![mimari](docs-not-included)

## ⚠️ Etik ve Yasal Uyarı
Bu aracı **yalnızca kendi ağında ya da tarama için açık izin aldığın ortamlarda**
kullan. İzinsiz port taraması birçok ülkede suçtur. Araç bir açığı **istismar etmez**;
yalnızca keşif, tespit ve raporlama yapar.

---

## Özellikler
- **🛡️ GERÇEK CVE tespiti (öne çıkan)** — `nmap -sV` ile gerçek servis+sürüm+CPE
  tespiti, ardından **canlı NVD (NIST National Vulnerability Database) API** sorgusu.
  Bulgular tahmin değil, o sürüme ait **gerçek CVE numaraları + gerçek CVSS puanları**;
  her CVE arayüzden `nvd.nist.gov`'a tıklanabilir. Yedek kaynak: CIRCL CVE-Search.
- **Canlı web arayüzü** — koyu tema, cihazlar tarandıkça anlık dolan kartlar (SSE)
- **Ağ keşfi** — paralel *ping sweep* + ARP tablosu ile canlı cihazlar
- **4 tarama modu** — 🛡️ Gerçek CVE (nmap+NVD), Hızlı (banner ipuçları), Tam (1–1024), Demo
- **Cihaz parmak izi** — MAC OUI'den üretici + porta/banner'a göre cihaz tipi
- **Riskli port analizi** — Telnet, TR-069, DVR portları vb. (gerçek gözlem, Mirai vektörleri)
- **Risk skorlama** — gerçek CVSS'e dayalı 0–100 puan + Kritik/Ciddi/Uyarı/Düşük
- **📟 Canlı log konsolu** — arka planda ne yaptığını (ping, port, nmap, NVD sorgusu,
  cihaz sonuçları) terminal gibi anlık akıtır (SSE).
- **📥 Cihazdan firmware/config ÇEKME** — taranan cihazın bilinen indirme/yedek uç noktalarını
  (`/rom-0`, `/backupsettings.cgi`, Hikvision/Dahua config yolları, `/firmware.bin`…) yoklar.
  Deep taramada **otomatik** dener; korumasız (kimlik doğrulamasız) olanı **zafiyet** olarak
  raporlar ve cihaz kartındaki **"⬇️ Bu cihazdan firmware/config çekmeyi dene"** butonuyla
  dosyayı `.bin` olarak çeker → indir + analiz et. (Çoğu cihaz kimlik doğrulama ister; korumasız
  olması başlı başına ciddi bir bulgudur.)
- **⬇️ Firmware indirme (URL'den)** — bir URL'den (satıcı firmware linki ya da cihaz uç noktası)
  firmware imajını sunucuya çeker ve sana **`.bin` olarak indirir** (kendin elle analiz etmen
  için). Canlı indirme logu + SHA-256 + tek tıkla yerleşik analizciye gönderme.
- **🔬 Firmware analizi** — iki katman:
  - **Ağ üzerinden:** cihaza dokunmadan açık HTTP/UPnP'den model & firmware sürümü tespiti
    (Server başlığı, auth realm, sayfa başlığı, UPnP device XML) → cihaz kartında görünür.
  - **İmaj statik analizi:** bir firmware imajı (.bin/.img) yükle → **binwalk** ile gömülü
    dosya sistemleri (SquashFS/CramFS/JFFS2…), **entropi** (şifreli mi?), **strings** ile
    sabit-kodlu parolalar/özel anahtarlar/telnet, ve eski bileşenler (busybox, dropbear,
    OpenSSL…) → **NVD'den gerçek CVE**. Kendi canlı log akışı vardır.
- **Grafikler** — risk dağılımı + en sık açık portlar
- **JSON rapor** — tek tıkla indirilebilir
- **🎬 Demo modu** — ağa dokunmadan gerçekçi cihazlar üretir (sunum provası için)

### Firmware analizini denemek (sunum için hazır örnek)
```bash
python3 samples/make_demo_firmware.py        # samples/demo_firmware.bin üretir
```
Arayüzde **🔬 Firmware Analizi** bölümüne bu dosyayı sürükle. Çıkan gerçek bulgular:
gömülü SquashFS + U-Boot, sabit-kodlu root/admin parolası, RSA özel anahtar, telnetd,
ve OpenSSL 1.0.1e → **CVE-2014-0160 (Heartbleed)**, busybox/dropbear/lighttpd/dnsmasq CVE'leri.
> Örnek imaj çalıştırılabilir firmware değildir; sadece analiz motorunu besleyen zararsız bir demodur.

### "Gerçek mi?" — evet, bulgular gerçek
- **Cihaz/IP/MAC/port** → ağdan doğrudan ölçüm (ping, ARP, TCP).
- **Servis+sürüm** → `nmap -sV` (endüstri standardı tespit, banner tahmini değil).
- **Zafiyetler** → **NVD/NIST canlı API**'sinden gerçek CVE + CVSS. Kaynak her bulguda yazar.
- Güncel/yamalı bir servis varsa **temiz** raporlanır (yanlış alarm üretmez).

> **Hız ipucu:** NVD anahtarsız ~5 istek/30 sn ile sınırlar. Ücretsiz bir anahtar alıp
> `export NVD_API_KEY=xxxx` yaparsan Gerçek-CVE modu çok daha hızlı çalışır.
> Anahtar: https://nvd.nist.gov/developers/request-an-api-key

## Kurulum
Tek bağımlılık **Flask** (nmap yalnızca "Derin" modda opsiyonel):
```bash
cd iot-scanner
pip install flask          # kuruluysa atla
python3 app.py             # http://127.0.0.1:5000
```
Tarayıcıda **http://127.0.0.1:5000** adresini aç.

> ICMP ping ve ARP okuma için bazı sistemlerde `sudo python3 app.py` gerekebilir.
> Farklı port için: `python3 app.py --port 8000`

## Mimari
```
iot-scanner/
├─ app.py                 # Flask + SSE web sunucusu (REST API)
├─ scanner/
│  ├─ engine.py           # Tarama motoru: keşif→port→nmap→CVE→risk + canlı log
│  ├─ cve.py              # GERÇEK CVE arama: NVD + CIRCL API (canlı sorgu, önbellek)
│  ├─ firmware.py         # Firmware: ağ parmak izi + imaj statik analizi (binwalk/entropi/strings→CVE)
│  └─ vulndb.py           # OUI listesi, port & cihaz sözlükleri, riskli portlar
├─ samples/
│  └─ make_demo_firmware.py  # Sunum için zararsız örnek firmware üretir
├─ web/
│  └─ index.html          # Kontrol paneli (tek dosya: HTML+CSS+JS)
├─ iot_scanner.py         # (Bonus) Aynı işi yapan komut satırı sürümü
└─ signatures.py          # CLI sürümünün imza dosyası
```

### Boru hattı (6 aşama)
1. **Keşif** — `ping sweep` + `ip neigh` (ARP) → canlı host + MAC
2. **Port tarama** — TCP *connect* + banner grabbing (Derin modda `nmap -sV`)
3. **Parmak izi** — OUI → üretici; port+banner → cihaz tipi; IoT sınıflaması
4. **Denetim** — banner'dan sürüm çıkar → `vulndb` eşiğiyle karşılaştır + riskli port
5. **Risk** — CVSS ağırlıklı skor (kritik ×2.2, ciddi ×1.6) → 0–100 + seviye
6. **Rapor** — canlı arayüz + indirilebilir JSON

## REST API
| Uç nokta | Açıklama |
|----------|----------|
| `GET /` | Kontrol paneli |
| `GET /api/network` | Otomatik tespit edilen ağ (CIDR) |
| `POST /api/scan` | Tarama başlat `{network, mode}` |
| `POST /api/stop` | Taramayı durdur |
| `GET /api/status` | Anlık durum + sonuçlar (JSON) |
| `GET /api/stream` | Canlı olay akışı (SSE) |
| `GET /api/export` | JSON rapor indir |
| `POST /api/firmware` | Firmware analizi başlat (dosya yükleme veya `{path}`) |
| `GET /api/firmware/stream` | Firmware analizi canlı log (SSE) |
| `GET /api/firmware/status` | Firmware analizi durumu + sonuç |
| `POST /api/firmware/fetch` | URL'den firmware indir (`{url}`) — arka planda |
| `POST /api/firmware/grab` | Cihazdan firmware/config çekmeyi dene (`{ip}`) |
| `GET /api/firmware/fetch/stream` | İndirme/çekme canlı log (SSE) |
| `GET /api/firmware/download?name=` | İndirilen `.bin` dosyasını tarayıcıya sun |

> **Not:** Firmware analizi çok bileşenli imajlarda NVD hız limiti nedeniyle ~30 sn sürebilir
> (canlı log akışı ilerlemeyi gösterir). `NVD_API_KEY` tanımlanırsa çok daha hızlıdır.
> İndirilen firmware'ler proje içindeki `downloads/` klasörüne kaydedilir.

---

## 🎤 20 Dakikalık Sunum İçin İpuçları
1. **Aç:** `python3 app.py` → tarayıcıda panel. (Hız için önce `export NVD_API_KEY=...`)
2. **Ana demo — Gerçek CVE modu:** kendi ağında "🛡️ Gerçek CVE (nmap + NVD)" modunu
   seç, **Taramayı Başlat**. Cihazlar canlı dolar; en riskli cihaza tıkla → açık
   portlar + **gerçek CVE numaraları**. Bir CVE'ye tıkla → NVD sayfası açılır. Bu
   senin en güçlü kartın: "bulgular NIST'in resmi veritabanından, tahmin değil."
3. **Anlat:** nmap sürümü nasıl buluyor → CPE nedir → NVD'ye nasıl sorulur → CVSS ne demek.
4. **Ağ zayıfsa / internet yoksa:** "Demo" moduna geç — sunum yine dolu görünür
   (bunu demo olarak belirt; gerçek modun aynısını simüle eder).
5. **Kapanış:** JSON raporu indir; "gerçek/patch'li servisler temiz çıkıyor, bu da
   yanlış alarm üretmediğimizi gösterir" de.

### Raporda değinebileceğin teknik noktalar
- **TCP connect vs SYN scan** farkı (bu araç connect kullanır; neden root gerekmez?)
- **Banner grabbing** neden güvenilmez olabilir (üreticiler banner'ı gizler/yanıltır)
- İmza DB'sini **NVD/CVE API** ile canlı sorgulayarak nasıl geliştirilir
- **Telnet (23) / TR-069 (7547) / DVR portları** ve Mirai botnet ilişkisi
- **Risk skorlama** metodolojisi (CVSS ağırlıklandırma)
- `nmap` ile karşılaştırma; yanlış pozitif/negatif oranı

## Geliştirme Fikirleri
- OUI listesini IEEE veritabanından otomatik indirme
- CVE eşleşmesini NVD API ile çevrimiçi yapma
- UDP protokolleri (CoAP, SSDP, mDNS) taraması
- Tarama geçmişi ve zaman içinde karşılaştırma
- PDF/HTML rapor çıktısı

## Komut Satırı Sürümü (bonus)
Arayüzsüz, hızlı kullanım için:
```bash
python3 iot_scanner.py -n 192.168.1.0/24 -o sonuc.json
```
