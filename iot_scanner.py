#!/usr/bin/env python3
"""
iot_scanner.py
==============
Yerel ağdaki IoT cihazlarını tespit eden, portlarını tarayan ve çalışan
servislerin ESKİ / zafiyetli sürüm barındırıp barındırmadığını kontrol eden
eğitim amaçlı bir araç.

  1) Ağ keşfi   : ARP tablosu + ping sweep ile canlı cihazları bulur
  2) Sınıflama  : MAC OUI ve açık portlara göre "IoT olma ihtimalini" tahmin eder
  3) Port tarama: yaygın IoT portlarını TCP connect ile tarar
  4) Banner     : açık servislerden banner/versiyon bilgisi çeker
  5) Denetim    : signatures.py'deki eşiklere göre "eski sürüm mü?" der
  6) Rapor      : ekrana tablo + isteğe bağlı JSON çıktısı

ETİK / YASAL UYARI
------------------
Bu araç YALNIZCA sana ait ya da tarama için açık izin aldığın ağlarda
kullanılmalıdır. İzinsiz port taraması birçok ülkede yasa dışıdır.
Bu araç savunma / eğitim (bilgi güvenliği ödevi) amacıyla yazılmıştır.

Kullanım:
    python3 iot_scanner.py                      # ağı otomatik bul, tara
    python3 iot_scanner.py -n 192.168.1.0/24    # belirli ağı tara
    python3 iot_scanner.py -o sonuc.json        # sonucu JSON'a yaz
    python3 iot_scanner.py --full-ports         # 1-1024 portlarını da tara

Gereksinim: yalnızca Python 3 standart kütüphanesi. (nmap opsiyonel değil.)
"""

import argparse
import concurrent.futures
import ipaddress
import json
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

from signatures import (
    KNOWN_OUTDATED,
    IOT_OUI_PREFIXES,
    COMMON_IOT_PORTS,
)

# ----------------------------------------------------------------------------- #
# Yardımcı: sürüm karşılaştırma
# ----------------------------------------------------------------------------- #
def parse_version(v):
    """'1.4.51' gibi bir metni karşılaştırılabilir sayı demetine çevirir."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def version_less_than(found, threshold):
    """found < threshold ise True. Eksik alanları 0 sayar."""
    a = parse_version(found)
    b = parse_version(threshold)
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return a < b


# ----------------------------------------------------------------------------- #
# 1) Ağ keşfi
# ----------------------------------------------------------------------------- #
def detect_local_network():
    """Varsayılan arayüzden yerel /24 ağını tahmin eder (ör. 192.168.1.0/24)."""
    try:
        # İnternete çıkışta kullanılan yerel IP'yi öğren (paket göndermez).
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
        return str(net)
    except Exception:
        return "192.168.1.0/24"


def ping(host, timeout=1):
    """Tek bir host'a ICMP ping atar. Canlıysa True."""
    try:
        # Linux ping: -c1 tek paket, -W timeout saniye
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(host)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return r.returncode == 0
    except Exception:
        return False


def ping_sweep(network, workers=64):
    """Ağdaki tüm host'lara paralel ping atıp canlı olanları döndürür."""
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())
    live = []
    print(f"[*] Ping sweep: {network} ({len(hosts)} adres taranıyor)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(ping, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            if fut.result():
                live.append(str(host))
                print(f"    [+] Canlı: {host}")
    return sorted(live, key=lambda x: parse_version(x))


def get_arp_table():
    """Sistem ARP tablosundan IP -> MAC eşlemesini okur."""
    mapping = {}
    try:
        out = subprocess.run(
            ["ip", "neigh"], capture_output=True, text=True
        ).stdout
        # Örnek satır: 192.168.1.10 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-f:]{17})", line)
            if m:
                mapping[m.group(1)] = m.group(2).upper()
    except Exception:
        # Yedek: geleneksel 'arp -n'
        try:
            out = subprocess.run(
                ["arp", "-n"], capture_output=True, text=True
            ).stdout
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9A-Fa-f:]{17})", line)
                if m:
                    mapping[m.group(1)] = m.group(2).upper()
        except Exception:
            pass
    return mapping


def guess_vendor(mac):
    """MAC OUI önekinden üretici tahmini yapar (IoT ipucu)."""
    if not mac:
        return None
    prefix = mac.upper()[:8]  # 'AA:BB:CC'
    return IOT_OUI_PREFIXES.get(prefix)


# ----------------------------------------------------------------------------- #
# 3) Port tarama + 4) Banner grabbing
# ----------------------------------------------------------------------------- #
def scan_port(ip, port, timeout=1.0):
    """TCP connect taraması. Açıksa banner'ı da çekmeye çalışır."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None  # kapalı / filtreli
            banner = grab_banner(s, port)
            return {"port": port, "banner": banner}
    except Exception:
        return None


def grab_banner(sock, port):
    """Açık bir soketten servis banner'ı okumaya çalışır."""
    try:
        sock.settimeout(2.0)
        # HTTP servislerini konuşturmak için basit bir istek gönder.
        if port in (80, 8080, 443, 8443, 5000, 9000, 49152):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024)
        return data.decode(errors="replace").strip()
    except Exception:
        return ""


def scan_host_ports(ip, ports, timeout=1.0, workers=50):
    """Bir host üzerinde verilen portları paralel tarar."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(scan_port, ip, p, timeout) for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)
    return sorted(open_ports, key=lambda x: x["port"])


# ----------------------------------------------------------------------------- #
# 5) Eski / zafiyetli sürüm denetimi
# ----------------------------------------------------------------------------- #
def extract_service_version(banner):
    """
    Banner içinden (servis, sürüm) çiftlerini yakalamaya çalışır.
    Örn: 'SSH-2.0-OpenSSH_7.4' -> ('openssh', '7.4')
         'Server: Apache/2.4.29' -> ('apache', '2.4.29')
    """
    findings = []
    if not banner:
        return findings

    patterns = [
        (r"OpenSSH[_/](\d+\.\d+[\w.]*)", "openssh"),
        (r"dropbear[_ /]?(\d{4}\.\d+)", "dropbear"),
        (r"Apache/(\d+\.\d+\.\d+)", "apache"),
        (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
        (r"lighttpd/(\d+\.\d+\.\d+)", "lighttpd"),
        (r"GoAhead[- ]?(?:Webs)?/?(\d+\.\d+\.\d+)?", "goahead"),
        (r"Boa/(\d+\.\d+[\w.]*)", "boa"),
        (r"BusyBox[ v]*(\d+\.\d+\.\d+)", "busybox"),
        (r"vsftpd (\d+\.\d+\.\d+)", "vsftpd"),
        (r"mosquitto[ /]?(\d+\.\d+\.\d+)", "mosquitto"),
    ]
    for pattern, service in patterns:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            version = m.group(1) if m.lastindex else None
            findings.append((service, version))
    return findings


def audit_versions(open_ports):
    """
    Açık portların banner'larını sürüm imzalarıyla karşılaştırır.
    Eski/zafiyetli bulgular listesi döndürür.
    """
    issues = []
    for entry in open_ports:
        banner = entry.get("banner", "")
        for service, version in extract_service_version(banner):
            for sig in KNOWN_OUTDATED:
                if sig["service"] != service:
                    continue
                # Sürüm okunamadıysa da uyarı ver (bakımsız servisler için).
                if version is None:
                    issues.append({
                        "port": entry["port"],
                        "service": service,
                        "version": "bilinmiyor",
                        "severity": "UYARI",
                        "note": sig["note"] + " (Sürüm okunamadı; elle doğrula.)",
                    })
                elif version_less_than(version, sig["bad_below"]):
                    issues.append({
                        "port": entry["port"],
                        "service": service,
                        "version": version,
                        "severity": "ESKİ SÜRÜM",
                        "note": f"{service} {version} < güvenli {sig['bad_below']}. {sig['note']}",
                    })
    return issues


# ----------------------------------------------------------------------------- #
# 2) IoT sınıflama
# ----------------------------------------------------------------------------- #
def classify_iot(vendor, open_ports):
    """
    Cihazın IoT olma ihtimalini kaba bir skorla tahmin eder.
    (OUI eşleşmesi + tipik IoT portları)
    """
    score = 0
    reasons = []
    if vendor:
        score += 2
        reasons.append(f"Üretici OUI: {vendor}")
    iot_ports_hit = [p["port"] for p in open_ports if p["port"] in COMMON_IOT_PORTS]
    for p in iot_ports_hit:
        # Telnet, RTSP, MQTT, CoAP gibi portlar güçlü IoT sinyali.
        if p in (23, 554, 1883, 5683, 8883):
            score += 2
        else:
            score += 1
        reasons.append(f"Açık IoT portu {p} ({COMMON_IOT_PORTS[p]})")
    likely = score >= 2
    return {"likely_iot": likely, "score": score, "reasons": reasons}


# ----------------------------------------------------------------------------- #
# Raporlama
# ----------------------------------------------------------------------------- #
def print_report(results):
    print("\n" + "=" * 70)
    print("  IoT AĞ TARAMA RAPORU")
    print("  Tarih:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 70)
    if not results:
        print("\n  Canlı cihaz bulunamadı.\n")
        return

    for dev in results:
        tag = "MUHTEMEL IoT" if dev["iot"]["likely_iot"] else "Cihaz"
        print(f"\n{tag}  {dev['ip']}   MAC: {dev.get('mac', '-')}")
        if dev.get("vendor"):
            print(f"    Üretici : {dev['vendor']}")
        print(f"    IoT skoru: {dev['iot']['score']}  ({', '.join(dev['iot']['reasons']) or 'ipucu yok'})")

        if dev["open_ports"]:
            print("    Açık portlar:")
            for p in dev["open_ports"]:
                svc = COMMON_IOT_PORTS.get(p["port"], "")
                banner = (p["banner"][:60] + "…") if len(p.get("banner", "")) > 60 else p.get("banner", "")
                banner = banner.replace("\n", " ").replace("\r", " ")
                print(f"      - {p['port']:>5}/tcp  {svc:<30} {banner}")
        else:
            print("    Açık port bulunamadı.")

        if dev["issues"]:
            print("    [!] ESKİ/ZAFİYETLİ SÜRÜM BULGULARI:")
            for iss in dev["issues"]:
                print(f"      [{iss['severity']}] port {iss['port']} {iss['service']} "
                      f"{iss['version']}")
                print(f"          → {iss['note']}")
        else:
            print("    [OK] Bilinen eski-sürüm imzası eşleşmedi.")

    # Özet
    total = len(results)
    iot_count = sum(1 for d in results if d["iot"]["likely_iot"])
    vuln_count = sum(1 for d in results if d["issues"])
    print("\n" + "-" * 70)
    print(f"  ÖZET: {total} cihaz | {iot_count} muhtemel IoT | {vuln_count} cihazda eski-sürüm bulgusu")
    print("-" * 70 + "\n")


# ----------------------------------------------------------------------------- #
# Ana akış
# ----------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Yerel ağdaki IoT cihazlarını tespit edip eski sürüm denetimi yapar (eğitim amaçlı)."
    )
    ap.add_argument("-n", "--network", help="Taranacak ağ (CIDR), ör: 192.168.1.0/24")
    ap.add_argument("-o", "--output", help="Sonucu JSON dosyasına yaz")
    ap.add_argument("--full-ports", action="store_true",
                    help="Yaygın IoT portları yerine 1-1024 arası tam tarama")
    ap.add_argument("--timeout", type=float, default=1.0, help="Port bağlantı zaman aşımı (sn)")
    args = ap.parse_args()

    print("""
  ┌────────────────────────────────────────────────┐
  │   IoT Ağ Keşif ve Eski-Sürüm Denetim Aracı       │
  │   (Bilgi Güvenliği - Eğitim Amaçlı)              │
  │   Yalnızca izinli/kendi ağınızda kullanın.       │
  └────────────────────────────────────────────────┘
""")

    network = args.network or detect_local_network()
    ports = list(range(1, 1025)) if args.full_ports else sorted(COMMON_IOT_PORTS.keys())

    start = time.time()

    # 1) Keşif
    live_hosts = ping_sweep(network)
    arp = get_arp_table()

    # 2-5) Her canlı host için tarama + denetim
    results = []
    print(f"\n[*] {len(live_hosts)} cihazda port taraması yapılıyor ({len(ports)} port/cihaz)...")
    for ip in live_hosts:
        mac = arp.get(ip)
        vendor = guess_vendor(mac)
        open_ports = scan_host_ports(ip, ports, timeout=args.timeout)
        iot = classify_iot(vendor, open_ports)
        issues = audit_versions(open_ports)
        results.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "open_ports": open_ports,
            "iot": iot,
            "issues": issues,
        })

    # 6) Rapor
    print_report(results)
    print(f"[*] Tarama {time.time() - start:.1f} sn sürdü.")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(
                {"scanned_at": datetime.now().isoformat(),
                 "network": network,
                 "results": results},
                f, ensure_ascii=False, indent=2,
            )
        print(f"[*] JSON çıktısı yazıldı: {args.output}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Kullanıcı tarafından durduruldu.")
        sys.exit(1)
