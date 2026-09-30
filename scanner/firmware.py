"""
firmware.py
===========
İki tür firmware analizi:

1) fingerprint_network(ip, open_ports)
   Ağ üzerinden firmware/model TESPİTİ — cihaza dokunmadan, yalnızca zaten
   AÇIK olan HTTP/UPnP portlarından model & firmware sürümü ipuçları toplar
   (Server başlığı, HTTP kimlik doğrulama realm'i, <title>, UPnP device XML).

2) analyze(path, log)
   İndirilen bir firmware İMAJININ statik analizi (offline). Gerçek firmware
   güvenlik analizinin yaptığı işler:
     - dosya türü, boyut, SHA-256, entropi (şifreli/sıkıştırılmış mı?)
     - binwalk ile gömülü dosya sistemleri / sıkıştırma / bootloader / sertifika
     - strings ile: sabit-kodlu parolalar, özel anahtarlar, /etc/passwd/shadow,
       telnet, URL/IP'ler, bileşen sürümleri
     - tespit edilen bileşenleri (busybox, dropbear, openssl…) NVD'de GERÇEK
       CVE için sorgular
     - bulguları önem derecesiyle listeler + firmware risk skoru

ETİK: Yalnızca sana ait / analiz izni olan firmware imajlarını incele.
"""

import hashlib
import json
import math
import os
import re
import socket
import subprocess
import tempfile
import urllib.request

from . import cve

MAX_SIZE = 400 * 1024 * 1024          # 400 MB üst sınır
STRINGS_LIMIT = 4 * 1024 * 1024       # strings için taranacak azami çıktı

# --------------------------------------------------------------------------- #
# Cihazdan firmware/config çekmek için bilinen HTTP uç noktaları.
# (kind: firmware imajı mı, config/yedek mi; note: hangi cihaz ailesi)
# --------------------------------------------------------------------------- #
FIRMWARE_ENDPOINTS = [
    # router / gateway config yedekleri (çoğu sabit-kodlu parola/anahtar içerir)
    ("/backupsettings.cgi",              "config",   "Netgear yedek"),
    ("/rom-0",                           "config",   "ZyXEL/TP-Link rom-0 (klasik açık)"),
    ("/config.bin",                      "config",   "Genel router config"),
    ("/backup.bin",                      "config",   "Genel yedek"),
    ("/backup.cfg",                      "config",   "Genel yedek (cfg)"),
    ("/configbackup.bin",                "config",   "Config yedeği"),
    ("/cgi-bin/export_settings",         "config",   "CGI ayar dışa aktarımı"),
    ("/cgi-bin/backup",                  "config",   "CGI yedek"),
    ("/goform/backup",                   "config",   "Tenda/goform yedek"),
    ("/download/config",                 "config",   "Config indirme"),
    ("/tmp/config.bin",                  "config",   "Geçici config"),
    ("/nvram.bin",                       "config",   "NVRAM dökümü"),
    ("/system.cfg",                      "config",   "Ubiquiti system.cfg"),
    # kamera / DVR
    ("/System/configurationFile",        "config",   "Hikvision config (CVE-2017-7921)"),
    ("/configManager.backup",            "config",   "Dahua config yedeği"),
    # firmware imajı doğrudan
    ("/firmware.bin",                    "firmware", "Doğrudan firmware imajı"),
    ("/image.bin",                       "firmware", "Firmware imajı"),
    ("/upload/firmware.bin",             "firmware", "Firmware imajı"),
    ("/fwupgrade/firmware.bin",          "firmware", "Firmware yükseltme imajı"),
]


# =========================================================================== #
# 0) FIRMWARE İNDİRME (URL'den .bin çek → elle analiz için kaydet)
# =========================================================================== #
def fetch_url(url, dest_dir, log=None, filename=None):
    """
    Verilen URL'den firmware imajını indirir ve dest_dir'e .bin olarak kaydeder.
    Kullanıcının kendi tarayıcısına indirebilmesi + yerleşik analizciye
    gönderebilmesi için dosya yolunu döndürür. Akış (streaming) + boyut sınırı.

    Tipik kaynaklar: satıcı firmware indirme linki, ya da bir cihazın
    yedek/indirme uç noktası (ör. router 'backup settings').
    """
    def _log(m, lvl="info"):
        if log:
            log(m, lvl)

    res = {"ok": False, "path": "", "name": "", "size": 0, "sha256": "",
           "type": "", "error": ""}
    if not re.match(r"^https?://", url or "", re.I):
        res["error"] = "Geçerli bir http(s) URL girin."
        return res

    os.makedirs(dest_dir, exist_ok=True)
    if not filename:
        base = url.rstrip("/").split("/")[-1].split("?")[0] or "firmware"
        filename = re.sub(r"[^A-Za-z0-9_.\-]", "_", base)
        if not re.search(r"\.(bin|img|trx|fw|hex|chk|w|pkg)$", filename, re.I):
            filename += ".bin"
    dest = os.path.join(dest_dir, filename)

    _log(f"İndiriliyor: {url}", "head")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "iot-scanner-edu/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            ctype = r.headers.get("Content-Type", "")
            clen = int(r.headers.get("Content-Length", 0) or 0)
            _log(f"Sunucu yanıtı: {getattr(r,'status',200)} · tür={ctype or '?'}"
                 + (f" · boyut={clen:,} bayt" if clen else ""))
            if clen and clen > MAX_SIZE:
                res["error"] = f"Dosya çok büyük ({clen} bayt > {MAX_SIZE})."
                _log(res["error"], "warn")
                return res
            h = hashlib.sha256()
            total = 0
            last_pct = -1
            with open(dest, "wb") as out:
                while True:
                    chunk = r.read(256 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_SIZE:
                        out.close()
                        os.unlink(dest)
                        res["error"] = "İndirme boyut sınırını aştı, iptal edildi."
                        _log(res["error"], "warn")
                        return res
                    out.write(chunk)
                    h.update(chunk)
                    if clen:
                        pct = int(total * 100 / clen)
                        if pct != last_pct and pct % 10 == 0:
                            _log(f"  indirildi: %{pct} ({total:,}/{clen:,} bayt)")
                            last_pct = pct
            res.update({"ok": True, "path": dest, "name": filename, "size": total,
                        "sha256": h.hexdigest(), "type": _file_type(dest)})
            _log(f"İndirme tamam: {filename} ({total:,} bayt) · SHA-256 {res['sha256'][:16]}…", "ok")
            _log(f"Dosya türü: {res['type']}")
            # firmware imzası taşıyor mu, kısa ipucu
            sigs = _magic_scan(dest, window=4 * 1024 * 1024)
            if sigs:
                _log("Firmware imzası bulundu: " +
                     ", ".join(sorted({s['description'].split()[0] for s in sigs})), "warn")
            else:
                _log("Bilinen firmware imzası ilk 4MB'de görülmedi (yine de analiz edebilirsiniz).")
            return res
    except Exception as e:  # noqa
        res["error"] = f"İndirme hatası: {e}"
        _log(res["error"], "warn")
        try:
            if os.path.exists(dest):
                os.unlink(dest)
        except Exception:
            pass
        return res


# =========================================================================== #
# 0b) CİHAZDAN FIRMWARE / CONFIG ÇEKMEYİ DENE
# =========================================================================== #
def _http_ports(open_ports):
    ports = {p["port"] for p in open_ports}
    out = []
    for p in (80, 8080, 8000, 81, 443, 8443, 8081, 8888):
        if p in ports:
            out.append((p, "https" if p in (443, 8443) else "http"))
    return out


def _looks_binary(data, ctype):
    """Yanıt HTML değil, ikili/indirilebilir bir dosya mı?"""
    if not data:
        return False
    ct = (ctype or "").lower()
    if any(k in ct for k in ("octet-stream", "application/octet", "binary",
                             "download", "x-binary", "force-download")):
        return True
    head = data[:512]
    low = head.lstrip()[:15].lower()
    if low.startswith((b"<!doctype", b"<html", b"<?xml", b"{", b"<head")):
        return False
    # null bayt ya da yüksek oranda basılamayan karakter → ikili
    nonprint = sum(1 for b in head if b < 9 or (13 < b < 32))
    return (b"\x00" in head) or (nonprint > len(head) * 0.15)


def _probe_endpoint(ip, port, scheme, path, timeout=2.5, read=4096):
    import ssl
    url = f"{scheme}://{ip}:{port}{path}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "iot-scanner-edu/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            ctype = r.headers.get("Content-Type", "")
            clen = int(r.headers.get("Content-Length", 0) or 0)
            data = r.read(read)
            return {"url": url, "status": getattr(r, "status", 200),
                    "ctype": ctype, "size": clen or len(data),
                    "binary": _looks_binary(data, ctype)}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "ctype": "", "size": 0, "binary": False}
    except Exception:
        return None


def probe_device(ip, open_ports, log=None):
    """
    Cihazın bilinen firmware/config uç noktalarını yoklar (indirmeden).
    Döner: {"candidates":[...indirilebilir...], "findings":[...zafiyet...]}
    """
    def _log(m, lvl="info"):
        if log:
            log(m, lvl)

    candidates, findings = [], []
    hports = _http_ports(open_ports)
    if not hports:
        _log(f"[{ip}] HTTP portu yok — firmware/config uç noktası denenemiyor", "info")
        return {"candidates": candidates, "findings": findings}

    _log(f"[{ip}] firmware/config uç noktaları yoklanıyor ({len(FIRMWARE_ENDPOINTS)} yol)…", "head")
    for port, scheme in hports[:4]:
        for path, kind, note in FIRMWARE_ENDPOINTS:
            res = _probe_endpoint(ip, port, scheme, path)
            if not res:
                continue
            st = res["status"]
            if st == 200 and res["binary"]:
                sev = "critical" if kind == "firmware" else "serious"
                _log(f"[{ip}:{port}] AÇIK: {path} → indirilebilir {kind} "
                     f"({res['size']:,} bayt) — {note}", "warn")
                candidates.append({"ip": ip, "port": port, "scheme": scheme,
                                   "path": path, "url": res["url"], "kind": kind,
                                   "size": res["size"], "note": note})
                findings.append({
                    "severity": sev, "kind": "exposed-endpoint",
                    "title": f"Kimlik doğrulamasız {kind} indirilebilir: {path}",
                    "detail": f"{note}. Bu uç nokta parola sormadan {res['size']:,} baytlık "
                              f"bir dosya döndürüyor — firmware/config sızıntısı.",
                    "port": port, "service": "http", "cvss": 8.6 if kind == "firmware" else 7.5,
                    "source": "firmware-grab"})
            elif st in (401, 403):
                _log(f"[{ip}:{port}] var ama korumalı ({st}): {path}")
                findings.append({
                    "severity": "warning", "kind": "protected-endpoint",
                    "title": f"{kind} uç noktası mevcut (kimlik doğrulamalı): {path}",
                    "detail": f"{note}. {st} döndü — endpoint var; zayıf/varsayılan parola ile "
                              f"erişilebilir olabilir.",
                    "port": port, "service": "http", "cvss": 4.0, "source": "firmware-grab"})
    if not candidates:
        _log(f"[{ip}] korumasız indirilebilir firmware/config bulunamadı", "ok")
    return {"candidates": candidates, "findings": findings}


def grab_from_device(ip, open_ports, dest_dir, log=None):
    """
    Cihazdan firmware/config ÇEKER: uç noktaları yoklar, korumasız (indirilebilir)
    olanları dest_dir'e .bin olarak kaydeder. Döner: {"saved":[...], "findings":[...]}
    """
    def _log(m, lvl="info"):
        if log:
            log(m, lvl)

    probe = probe_device(ip, open_ports, log=log)
    saved = []
    os.makedirs(dest_dir, exist_ok=True)
    for c in probe["candidates"]:
        safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", f"{ip}_{c['port']}{c['path']}")
        if not re.search(r"\.\w{1,5}$", safe):
            safe += ".bin"
        fn = f"grab_{safe}"
        res = fetch_url(c["url"], dest_dir, log=log, filename=fn)
        if res.get("ok"):
            res["kind"] = c["kind"]
            res["note"] = c["note"]
            saved.append(res)
    if saved:
        _log(f"[{ip}] {len(saved)} dosya çekildi ve kaydedildi (indir/analiz edebilirsiniz)", "head")
    else:
        _log(f"[{ip}] çekilebilecek korumasız dosya yok", "ok")
    return {"saved": saved, "findings": probe["findings"]}


# =========================================================================== #
# 1) AĞ ÜZERİNDEN FIRMWARE / MODEL PARMAK İZİ
# =========================================================================== #
def fingerprint_network(ip, open_ports):
    ports = {p["port"] for p in open_ports}
    info = {"model": "", "fw_version": "", "server": "", "source": "", "hints": []}

    http_ports = [p for p in (80, 8080, 8000, 8443, 443, 5000, 49152) if p in ports]
    for port in http_ports[:3]:
        scheme = "https" if port in (443, 8443) else "http"
        data = _http_head_get(ip, port, scheme)
        if not data:
            continue
        server = re.search(r"^Server:\s*(.+)$", data, re.I | re.M)
        realm = re.search(r'realm="?([^"\r\n]+)"?', data, re.I)
        title = re.search(r"<title>\s*(.+?)\s*</title>", data, re.I | re.S)
        if server and not info["server"]:
            info["server"] = server.group(1).strip()[:80]
            info["hints"].append(f"Server: {info['server']}")
        if realm:
            info["hints"].append(f"Auth realm: {realm.group(1).strip()[:60]}")
            if not info["model"]:
                info["model"] = realm.group(1).strip()[:60]
        if title:
            t = re.sub(r"\s+", " ", title.group(1))[:60]
            info["hints"].append(f"Sayfa başlığı: {t}")
            if not info["model"]:
                info["model"] = t
        # sürüm ipucu
        vm = re.search(r"(?:firmware|version|fw|v)[\s:_-]*([0-9]+\.[0-9][\w.\-]*)", data, re.I)
        if vm and not info["fw_version"]:
            info["fw_version"] = vm.group(1)
        if info["server"] or info["model"]:
            info["source"] = f"HTTP:{port}"
            break

    # UPnP device açıklaması (model/marka için zengin kaynak)
    if not info["model"] and ({1900, 49152, 5000} & ports):
        up = _upnp_describe(ip, ports)
        if up:
            info.update({k: v for k, v in up.items() if v and not info.get(k)})
            info["source"] = info["source"] or "UPnP"
    return info


def _http_head_get(ip, port, scheme, timeout=2.5):
    try:
        import ssl
        url = f"{scheme}://{ip}:{port}/"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "iot-scanner-edu/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            head = "".join(f"{k}: {v}\n" for k, v in r.headers.items())
            body = r.read(4096).decode(errors="replace")
            return head + "\n" + body
    except Exception as e:  # 401 vb. de başlık taşır
        h = getattr(e, "headers", None)
        if h:
            return "".join(f"{k}: {v}\n" for k, v in h.items())
        return ""


def _upnp_describe(ip, ports, timeout=2.5):
    for port in (49152, 5000, 1900, 80):
        if port not in ports and port != 1900:
            continue
        for path in ("/description.xml", "/rootDesc.xml", "/device.xml", "/upnp/desc.xml"):
            try:
                url = f"http://{ip}:{port}{path}"
                with urllib.request.urlopen(url, timeout=timeout) as r:
                    xml = r.read(8192).decode(errors="replace")
                out = {}
                for tag, key in (("modelName", "model"), ("modelNumber", "fw_version"),
                                 ("manufacturer", "server")):
                    m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.I | re.S)
                    if m:
                        out[key] = re.sub(r"\s+", " ", m.group(1)).strip()[:60]
                if out:
                    return out
            except Exception:
                continue
    return None


# =========================================================================== #
# 2) FIRMWARE İMAJI STATİK ANALİZİ
# =========================================================================== #

# Bileşen adı -> NVD CPE şablonu (sürüm sona eklenir)
_COMPONENT_CPE = {
    "busybox":  "cpe:/a:busybox:busybox:{v}",
    "dropbear": "cpe:/a:dropbear_ssh_project:dropbear_ssh:{v}",
    "openssl":  "cpe:/a:openssl:openssl:{v}",
    "openssh":  "cpe:/a:openbsd:openssh:{v}",
    "lighttpd": "cpe:/a:lighttpd:lighttpd:{v}",
    "dnsmasq":  "cpe:/a:thekelleys:dnsmasq:{v}",
    "curl":     "cpe:/a:haxx:curl:{v}",
    "wget":     "cpe:/a:gnu:wget:{v}",
    "zlib":     "cpe:/a:zlib:zlib:{v}",
    "uclibc":   "cpe:/a:uclibc:uclibc:{v}",
}

# Gömülü dosya sistemi / sıkıştırma magic imzaları (binwalk yoksa yedek)
_MAGICS = [
    (b"hsqs", "SquashFS dosya sistemi (little-endian)"),
    (b"sqsh", "SquashFS dosya sistemi (big-endian)"),
    (b"\x45\x3d\xcd\x28", "CramFS dosya sistemi"),
    (b"\x85\x19", "JFFS2 dosya sistemi"),
    (b"UBI#", "UBI/UBIFS dosya sistemi"),
    (b"\x27\x05\x19\x56", "U-Boot uImage başlığı"),
    (b"\x1f\x8b\x08", "gzip sıkıştırma"),
    (b"\xfd7zXZ\x00", "XZ sıkıştırma"),
    (b"\x5d\x00\x00", "LZMA sıkıştırma"),
    (b"BZh", "bzip2 sıkıştırma"),
    (b"ANDROID!", "Android boot image"),
    (b"\xd0\x0d\xfe\xed", "Device Tree Blob (DTB)"),
]


def analyze(path, log=None):
    def _log(m, lvl="info"):
        if log:
            log(m, lvl)

    res = {"ok": False, "path": path, "file": {}, "signatures": [],
           "findings": [], "components": [], "strings_sample": [],
           "risk_score": 0, "risk_level": "good", "error": ""}

    if not path or not os.path.isfile(path):
        res["error"] = "Dosya bulunamadı: " + str(path)
        return res
    size = os.path.getsize(path)
    if size == 0 or size > MAX_SIZE:
        res["error"] = f"Dosya boyutu uygun değil ({size} bayt, üst sınır {MAX_SIZE})."
        return res

    _log(f"Firmware analizi başladı: {os.path.basename(path)} ({size:,} bayt)", "head")

    # --- temel bilgiler ---
    _log("SHA-256 hesaplanıyor…")
    sha = _sha256(path)
    ftype = _file_type(path)
    _log(f"Dosya türü (file): {ftype}")
    ent = _entropy(path)
    ent_verdict = ("çok yüksek — büyük olasılıkla ŞİFRELİ" if ent >= 7.8 else
                   "yüksek — sıkıştırılmış/paketlenmiş" if ent >= 7.2 else
                   "orta/düşük — büyük olasılıkla açık (çıkarılabilir)")
    _log(f"Entropi: {ent:.2f}/8.0 → {ent_verdict}", "warn" if ent >= 7.8 else "ok")
    res["file"] = {"name": os.path.basename(path), "size": size, "sha256": sha,
                   "type": ftype, "entropy": round(ent, 2), "entropy_verdict": ent_verdict}

    # --- binwalk imza taraması ---
    _log("binwalk imza taraması çalıştırılıyor…")
    sigs = _binwalk(path)
    if not sigs:
        sigs = _magic_scan(path)   # yedek: kendi magic taramamız
    res["signatures"] = sigs
    for s in sigs[:12]:
        _log(f"  0x{s['offset']:X}: {s['description']}")
    fs_found = [s for s in sigs if s.get("kind") == "filesystem"]
    if fs_found:
        _log(f"{len(fs_found)} gömülü dosya sistemi bulundu "
             f"({', '.join(sorted({s['description'].split()[0] for s in fs_found}))})", "warn")

    # --- string tabanlı sırlar / bileşenler ---
    _log("strings çıkarılıyor ve sırlar/bileşenler taranıyor…")
    strings = _extract_strings(path)
    findings = _scan_secrets(strings)
    res["findings"].extend(findings)
    for f in findings:
        _log(f"  BULGU [{f['severity']}] {f['title']}", "warn")

    # --- bileşen sürümleri -> GERÇEK CVE (NVD) ---
    comps = _detect_components(strings)
    for c in comps:
        cpe = _COMPONENT_CPE[c["name"]].format(v=c["version"])
        _log(f"Bileşen: {c['name']} {c['version']} → NVD sorgulanıyor ({cpe})")
        cves = cve.lookup_cpe(cpe, min_cvss=7.0, limit=5)
        c["cves"] = cves
        if cves:
            _log(f"  {c['name']} {c['version']}: {len(cves)} gerçek CVE "
                 f"(en yüksek CVSS {cves[0]['cvss']})", "warn")
            res["findings"].append({
                "severity": cves[0]["severity"],
                "title": f"{c['name']} {c['version']} — {len(cves)} bilinen CVE",
                "detail": ", ".join(x["cve"] for x in cves[:5]),
                "kind": "component-cve"})
        else:
            _log(f"  {c['name']} {c['version']}: CVSS≥7 CVE yok", "ok")
    res["components"] = comps

    # örnek ilginç string'ler (UI'da göstermek için)
    res["strings_sample"] = _interesting_sample(strings)

    # --- risk skoru ---
    score = 0
    for f in res["findings"]:
        score += {"critical": 25, "serious": 15, "warning": 8, "good": 0}.get(f["severity"], 5)
    if fs_found:
        score += 5
    score = min(100, score)
    res["risk_score"] = score
    res["risk_level"] = ("critical" if score >= 60 else "serious" if score >= 35
                         else "warning" if score >= 10 else "good")
    res["ok"] = True
    _log(f"Firmware analizi bitti — {len(res['findings'])} bulgu, risk {score} "
         f"({res['risk_level']})", "head")
    return res


# --- yardımcılar ---
def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_type(path):
    try:
        return subprocess.run(["file", "-b", path], capture_output=True, text=True,
                              timeout=15).stdout.strip()[:120]
    except Exception:
        return "bilinmiyor"


def _entropy(path, sample=8 * 1024 * 1024):
    """Dosyanın (örneklenmiş) Shannon entropisi (0-8)."""
    counts = [0] * 256
    total = 0
    with open(path, "rb") as f:
        data = f.read(sample)
    if not data:
        return 0.0
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def _binwalk(path):
    """binwalk -l JSON çıktısını parse eder. binwalk v3 uyumlu, defansif."""
    sigs = []
    if not _which("binwalk"):
        return sigs
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            logp = tf.name
        subprocess.run(["binwalk", "-l", logp, path],
                       capture_output=True, text=True, timeout=120)
        with open(logp) as f:
            raw = f.read()
        os.unlink(logp)
        data = json.loads(raw) if raw.strip() else []
        # binwalk v3 formatı: [{"Analysis":{"file_map":[{...}]}}] ya da liste
        entries = _flatten_binwalk(data)
        for e in entries:
            desc = (e.get("description") or e.get("name") or "").strip()
            off = e.get("offset", 0)
            if not desc:
                continue
            sigs.append({"offset": int(off), "description": desc[:120],
                         "kind": _classify_sig(desc)})
    except Exception:
        pass
    return sigs


def _flatten_binwalk(data):
    out = []
    if isinstance(data, dict):
        data = [data]
    for item in (data or []):
        if not isinstance(item, dict):
            continue
        ana = item.get("Analysis") or item.get("analysis") or item
        fmap = ana.get("file_map") if isinstance(ana, dict) else None
        if isinstance(fmap, list):
            out.extend(x for x in fmap if isinstance(x, dict))
        elif isinstance(item, dict) and ("description" in item or "offset" in item):
            out.append(item)
    return out


def _classify_sig(desc):
    d = desc.lower()
    if any(k in d for k in ("squashfs", "cramfs", "jffs", "ubi", "yaffs", "ext2", "ext3", "ext4", "romfs")):
        return "filesystem"
    if any(k in d for k in ("gzip", "lzma", "xz", "bzip", "zlib", "lz4", "compress")):
        return "compression"
    if any(k in d for k in ("uimage", "u-boot", "uboot", "bootloader", "vmlinux", "kernel")):
        return "boot"
    if any(k in d for k in ("certificate", "private key", "public key", "rsa", "pem", "crypto")):
        return "crypto"
    return "other"


def _magic_scan(path, window=64 * 1024 * 1024):
    """binwalk yoksa: kendi magic imza taramamız (ilk pencere)."""
    sigs = []
    with open(path, "rb") as f:
        data = f.read(window)
    for magic, desc in _MAGICS:
        idx = data.find(magic)
        if idx != -1:
            sigs.append({"offset": idx, "description": desc, "kind": _classify_sig(desc)})
    return sigs


def _extract_strings(path):
    """strings ikilisiyle metin çıkarır (yoksa pure-python)."""
    try:
        out = subprocess.run(["strings", "-n", "6", path], capture_output=True,
                             text=True, timeout=120).stdout
        return out[:STRINGS_LIMIT]
    except Exception:
        # pure-python yedek
        buf, res, n = bytearray(), [], 0
        with open(path, "rb") as f:
            for b in f.read(64 * 1024 * 1024):
                if 32 <= b < 127:
                    buf.append(b)
                else:
                    if len(buf) >= 6:
                        res.append(buf.decode())
                        n += len(buf)
                    buf.clear()
                    if n > STRINGS_LIMIT:
                        break
        return "\n".join(res)


# sırlar / tehlikeli göstergeler
_SECRET_RULES = [
    ("critical", "Özel anahtar gömülü (PRIVATE KEY)",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("critical", "/etc/shadow karma parola satırı",
     r"^\w+:\$[0-9a-z]\$[^\s:]{8,}:", ),
    ("serious", "/etc/passwd root kabuk satırı",
     r"root:[^:]*:0:0:"),
    ("serious", "Sabit-kodlu parola ataması",
     r"(?i)(?:password|passwd|pwd|admin_pass)\s*[=:]\s*[\"']?[^\s\"';]{4,}"),
    ("serious", "Sertifika gömülü (CERTIFICATE)",
     r"-----BEGIN CERTIFICATE-----"),
    ("warning", "Telnet servisi (telnetd) referansı",
     r"\btelnetd\b"),
    ("warning", "API anahtarı / token benzeri dize",
     r"(?i)(?:api[_-]?key|secret[_-]?key|token)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{16,}"),
    ("warning", "Sabit-kodlu URL/uç nokta (güncelleme sunucusu vb.)",
     r"https?://[A-Za-z0-9\.\-]{4,}(?:/[\w\.\-/]*)?"),
]


def _scan_secrets(text):
    findings = []
    seen = set()
    for sev, title, pat in _SECRET_RULES:
        matches = re.findall(pat, text, re.MULTILINE)
        if matches:
            if title in seen:
                continue
            seen.add(title)
            sample = ""
            m = re.search(pat, text, re.MULTILINE)
            if m:
                sample = m.group(0)[:80].replace("\n", " ")
            findings.append({"severity": sev, "title": title,
                             "detail": f"{len(matches)} eşleşme. örn: {sample}",
                             "kind": "secret"})
    return findings


def _detect_components(text):
    """Firmware içindeki bilinen bileşenlerin sürümlerini yakalar."""
    comps = []
    seen = set()
    patterns = [
        ("busybox",  r"BusyBox\s+v?(\d+\.\d+\.\d+)"),
        ("dropbear", r"[Dd]ropbear[\w /]*?(\d{4}\.\d+)"),
        ("openssl",  r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)"),
        ("openssh",  r"OpenSSH[_/](\d+\.\d+)"),
        ("lighttpd", r"lighttpd/(\d+\.\d+\.\d+)"),
        ("dnsmasq",  r"dnsmasq[- ]?(\d+\.\d+)"),
        ("curl",     r"curl/(\d+\.\d+\.\d+)"),
        ("wget",     r"Wget/(\d+\.\d+\.\d+)"),
        ("zlib",     r"zlib\s+(\d+\.\d+\.\d+)"),
        ("uclibc",   r"uClibc[- ]?(\d+\.\d+\.\d+)"),
    ]
    for name, pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m and name not in seen:
            seen.add(name)
            comps.append({"name": name, "version": m.group(1), "cves": []})
    return comps


def _interesting_sample(text, limit=25):
    """UI'da göstermek için ilginç string örnekleri."""
    keys = ("password", "passwd", "admin", "root", "login", "telnet", "http://",
            "https://", "BEGIN", "firmware", "version", "key", "secret", "mtd", "nvram")
    out = []
    for line in text.splitlines():
        s = line.strip()
        if 6 <= len(s) <= 120 and any(k in s.lower() for k in keys):
            out.append(s)
            if len(out) >= limit:
                break
    return out


def _which(x):
    from shutil import which
    return which(x)
