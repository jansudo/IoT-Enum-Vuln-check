"""
engine.py
=========
IoT tarama motoru. Bir Scan nesnesi tüm durumu (ilerleme, cihazlar, olay akışı)
tutar; ScanEngine taramayı arka planda çalıştırır ve canlı olaylar üretir.

Aşamalar:
  1) discovery  : ping sweep + ARP -> canlı host + MAC
  2) portscan   : TCP connect + banner grabbing (opsiyonel nmap -sV)
  3) fingerprint: üretici (OUI) + cihaz tipi tahmini
  4) audit      : eski-sürüm denetimi + riskli port analizi
  5) risk       : cihaz başına 0-100 risk skoru

ETİK: Yalnızca kendi/izinli ağda kullanın.
"""

import concurrent.futures
import ipaddress
import queue
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime

from . import cve
from . import firmware as fw
from .vulndb import (
    KNOWN_OUTDATED, IOT_OUI_PREFIXES, COMMON_IOT_PORTS,
    RISKY_PORTS, DEVICE_FINGERPRINTS,
)

# --------------------------------------------------------------------------- #
# Sürüm karşılaştırma yardımcıları
# --------------------------------------------------------------------------- #
def _ver(v):
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts) if parts else (0,)


def version_less_than(found, threshold):
    a, b = _ver(found), _ver(threshold)
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


# --------------------------------------------------------------------------- #
# Scan: tek bir taramanın paylaşılan durumu (thread-safe)
# --------------------------------------------------------------------------- #
class Scan:
    def __init__(self, network, mode):
        self.id = uuid.uuid4().hex[:8]
        self.network = network
        self.mode = mode                    # quick | full | deep
        self.state = "hazır"                # hazır|keşif|tarama|analiz|bitti|hata|durduruldu
        self.started_at = datetime.now().isoformat(timespec="seconds")
        self.finished_at = None
        self.progress = 0.0                 # 0-100
        self.phase = ""
        self.devices = []                   # tamamlanmış cihaz kayıtları
        self.error = None
        self._lock = threading.RLock()   # snapshot() -> summary() yeniden-girişli kilit
        self._events = queue.Queue()        # SSE olay kuyruğu
        self._stop = threading.Event()

    # --- olay yayınlama (SSE) ---
    def emit(self, kind, **data):
        self._events.put({"kind": kind, "ts": time.time(), **data})

    def log(self, msg, level="info"):
        """Canlı log konsoluna satır gönderir (arka planda ne yapıldığını gösterir)."""
        self.emit("log", level=level,
                  time=datetime.now().strftime("%H:%M:%S"), msg=msg)

    def events(self):
        return self._events

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.is_set()

    def set(self, **kw):
        with self._lock:
            for k, v in kw.items():
                setattr(self, k, v)

    def add_device(self, dev):
        with self._lock:
            self.devices.append(dev)

    def summary(self):
        with self._lock:
            devs = list(self.devices)
        iot = [d for d in devs if d["is_iot"]]
        vuln = [d for d in devs if d["vulns"]]
        total_open = sum(len(d["open_ports"]) for d in devs)
        risk_buckets = {"critical": 0, "serious": 0, "warning": 0, "good": 0}
        for d in devs:
            risk_buckets[d["risk_level"]] += 1
        # en yaygın açık portlar
        port_counter = {}
        for d in devs:
            for p in d["open_ports"]:
                port_counter[p["port"]] = port_counter.get(p["port"], 0) + 1
        top_ports = sorted(port_counter.items(), key=lambda x: -x[1])[:8]
        return {
            "total": len(devs), "iot": len(iot), "vuln": len(vuln),
            "open_ports": total_open, "risk_buckets": risk_buckets,
            "top_ports": [{"port": p, "count": c,
                           "label": COMMON_IOT_PORTS.get(p, "")} for p, c in top_ports],
            "avg_risk": round(sum(d["risk_score"] for d in devs) / len(devs), 1) if devs else 0,
        }

    def snapshot(self):
        with self._lock:
            return {
                "id": self.id, "network": self.network, "mode": self.mode,
                "state": self.state, "phase": self.phase,
                "progress": round(self.progress, 1),
                "started_at": self.started_at, "finished_at": self.finished_at,
                "error": self.error, "devices": list(self.devices),
                "summary": self.summary(),
            }


# --------------------------------------------------------------------------- #
# ScanEngine
# --------------------------------------------------------------------------- #
class ScanEngine:
    PORT_PROFILES = {
        "quick": sorted(COMMON_IOT_PORTS.keys()),
        "full": list(range(1, 1025)),
        "deep": sorted(set(list(COMMON_IOT_PORTS.keys()) + list(range(1, 1025)))),
    }

    def __init__(self):
        self.current = None
        self._thread = None

    # ---- Ağ tespiti ----
    @staticmethod
    def detect_network():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return str(ipaddress.ip_network(ip + "/24", strict=False))
        except Exception:
            return "192.168.1.0/24"

    # ---- Taramayı başlat (arka plan thread) ----
    def start(self, network, mode="quick"):
        if self.current and self.current.state in ("keşif", "tarama", "analiz"):
            return self.current  # zaten çalışıyor
        scan = Scan(network, mode)
        self.current = scan
        self._thread = threading.Thread(target=self._run, args=(scan,), daemon=True)
        self._thread.start()
        return scan

    # ---- Ana akış ----
    def _run(self, scan):
        if scan.mode == "demo":
            return self._run_demo(scan)
        try:
            scan.set(state="keşif", phase="Canlı cihazlar aranıyor")
            scan.emit("phase", phase=scan.phase, state=scan.state)
            scan.log(f"Tarama başladı — ağ={scan.network} mod={scan.mode}", "head")
            scan.log(f"ping sweep gönderiliyor ({scan.network})…")
            hosts = self._discover(scan)
            scan.log(f"Keşif tamam: {len(hosts)} canlı cihaz bulundu", "ok")
            if scan.stopped():
                return self._finish(scan, "durduruldu")

            scan.log("ARP tablosu okunuyor (ip neigh) → MAC eşlemesi")
            arp = self._arp_table()
            ports = self.PORT_PROFILES[scan.mode]
            extra = " + NVD'den gerçek CVE sorgusu" if scan.mode == "deep" else ""
            scan.set(state="tarama",
                     phase=f"{len(hosts)} cihazda {len(ports)} port taranıyor{extra}")
            scan.emit("phase", phase=scan.phase, state=scan.state)

            for i, ip in enumerate(hosts):
                if scan.stopped():
                    return self._finish(scan, "durduruldu")
                scan.log(f"[{ip}] {len(ports)} port TCP-connect taranıyor…")
                dev = self._scan_host(scan, ip, arp.get(ip), ports)
                op = len(dev["open_ports"]); vn = len(dev["vulns"])
                lvl = "warn" if vn else "ok"
                scan.log(f"[{ip}] {dev['icon']} {dev['device_type']} · {op} açık port · "
                         f"{vn} bulgu · risk {dev['risk_score']} ({dev['risk_level']})", lvl)
                scan.add_device(dev)
                scan.emit("device", device=dev)
                scan.set(progress=10 + 85 * (i + 1) / max(len(hosts), 1))
                scan.emit("progress", progress=round(scan.progress, 1),
                          summary=scan.summary())

            scan.set(state="analiz", phase="Rapor derleniyor", progress=98)
            scan.emit("phase", phase=scan.phase, state=scan.state)
            self._finish(scan, "bitti")
        except Exception as e:  # noqa
            scan.set(state="hata", error=str(e))
            scan.emit("error", message=str(e))
            self._finish(scan, "hata")

    # ---- Demo modu: ağa DOKUNMADAN gerçekçi cihazlar üretir (sunum provası) ----
    def _run_demo(self, scan):
        import time as _t
        fixtures = [
            ("192.168.1.1",  "AC:84:C6:11:22:33", [
                {"port": 53, "banner": ""}, {"port": 80, "banner": "Server: lighttpd/1.4.45"},
                {"port": 7547, "banner": "TR-069 CWMP"}, {"port": 1900, "banner": "miniupnpd/1.8"}]),
            ("192.168.1.20", "B8:27:EB:aa:bb:cc", [
                {"port": 22, "banner": "SSH-2.0-OpenSSH_7.4"}, {"port": 80, "banner": "Server: Apache/2.4.29"}]),
            ("192.168.1.37", "EC:FA:BC:de:ad:01", [
                {"port": 80, "banner": "Server: Boa/0.94.13"}, {"port": 554, "banner": "RTSP/1.0 200 OK"},
                {"port": 23, "banner": ""}]),
            ("192.168.1.44", "50:C7:BF:0a:0b:0c", [
                {"port": 6668, "banner": "tuya"}, {"port": 80, "banner": "Server: GoAhead-Webs"}]),
            ("192.168.1.58", "AC:63:BE:77:88:99", [
                {"port": 443, "banner": "amazon-echo"}, {"port": 8080, "banner": ""}]),
            ("192.168.1.72", "00:17:88:12:34:56", [
                {"port": 80, "banner": "mosquitto 1.5.7"}, {"port": 1883, "banner": "MQTT"}]),
            ("192.168.1.90", "F0:9F:C2:ab:cd:ef", [
                {"port": 22, "banner": "SSH-2.0-OpenSSH_8.9"}, {"port": 443, "banner": "nginx/1.24.0"}]),
        ]
        scan.set(state="keşif", phase="Canlı cihazlar aranıyor (DEMO)")
        scan.emit("phase", phase=scan.phase, state=scan.state)
        scan.log("DEMO modu — ağa dokunulmuyor, gerçekçi örnek veri üretiliyor", "head")
        for i, (ip, _mac, _p) in enumerate(fixtures):
            if scan.stopped():
                return self._finish(scan, "durduruldu")
            scan.emit("discovered", ip=ip, count=i + 1)
            scan.log(f"canlı cihaz bulundu: {ip}")
            scan.set(progress=10 * (i + 1) / len(fixtures))
            _t.sleep(0.25)
        scan.set(state="tarama", phase=f"{len(fixtures)} cihaz taranıyor (DEMO)")
        scan.emit("phase", phase=scan.phase, state=scan.state)
        for i, (ip, mac, ports) in enumerate(fixtures):
            if scan.stopped():
                return self._finish(scan, "durduruldu")
            op = [{"port": p["port"], "service": COMMON_IOT_PORTS.get(p["port"], ""),
                   "banner": p["banner"], "product": "", "version": ""} for p in ports]
            vendor = self._vendor(mac)
            dtype, icon = self._device_type(op, vendor)
            vulns = self._audit(op)
            fw_eps = []
            # DEMO: router ve kamerada firmware/config çekme senaryosunu göster
            if ip == "192.168.1.1":
                fw_eps = [{"ip": ip, "port": 80, "scheme": "http", "path": "/rom-0",
                           "url": f"http://{ip}/rom-0", "kind": "config", "size": 16384,
                           "note": "ZyXEL/TP-Link rom-0 (klasik açık)"}]
                vulns = vulns + [{"severity": "serious", "kind": "exposed-endpoint",
                    "title": "Kimlik doğrulamasız config indirilebilir: /rom-0",
                    "detail": "ZyXEL/TP-Link rom-0. Parola sormadan 16.384 baytlık config "
                              "döndürüyor — sabit parola/anahtar sızıntısı.",
                    "port": 80, "service": "http", "cvss": 7.5, "source": "firmware-grab"}]
            elif ip == "192.168.1.37":
                fw_eps = [{"ip": ip, "port": 80, "scheme": "http",
                           "path": "/System/configurationFile",
                           "url": f"http://{ip}/System/configurationFile", "kind": "config",
                           "size": 40960, "note": "Hikvision config (CVE-2017-7921)"}]
            rs, rl, rf = self._risk(op, vulns)
            dev = {"ip": ip, "mac": mac, "vendor": vendor or "Bilinmiyor",
                   "device_type": dtype, "icon": icon,
                   "firmware": {"model": "", "fw_version": "", "source": ""},
                   "fw_endpoints": fw_eps,
                   "is_iot": self._is_iot(vendor, op, dtype), "open_ports": op,
                   "vulns": vulns, "risk_score": rs, "risk_level": rl, "risk_factors": rf}
            scan.add_device(dev)
            scan.emit("device", device=dev)
            scan.log(f"[{ip}] {icon} {dtype} · {len(op)} port · {len(vulns)} bulgu · "
                     f"risk {rs} ({rl})", "warn" if vulns else "ok")
            scan.set(progress=10 + 88 * (i + 1) / len(fixtures))
            scan.emit("progress", progress=round(scan.progress, 1), summary=scan.summary())
            _t.sleep(0.5)
        return self._finish(scan, "bitti")

    def _finish(self, scan, state):
        s = scan.summary()
        scan.log(f"Tarama {state.upper()} — {s['total']} cihaz, {s['vuln']} zafiyetli, "
                 f"{s['open_ports']} açık port, ort. risk {s['avg_risk']}",
                 "head" if state == "bitti" else "warn")
        scan.set(state=state, phase="Tamamlandı" if state == "bitti" else state,
                 progress=100, finished_at=datetime.now().isoformat(timespec="seconds"))
        scan.emit("done", state=state, summary=scan.summary())
        return scan

    # ---- 1) Keşif ----
    def _discover(self, scan):
        net = ipaddress.ip_network(scan.network, strict=False)
        hosts = [str(h) for h in net.hosts()]
        live = []
        total = len(hosts)
        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
            futs = {ex.submit(self._ping, h): h for h in hosts}
            for fut in concurrent.futures.as_completed(futs):
                if scan.stopped():
                    break
                done += 1
                h = futs[fut]
                if fut.result():
                    live.append(h)
                    scan.emit("discovered", ip=h, count=len(live))
                scan.set(progress=10 * done / max(total, 1))
                if done % 16 == 0:
                    scan.emit("progress", progress=round(scan.progress, 1),
                              summary=scan.summary())
        return sorted(live, key=lambda x: _ver(x))

    @staticmethod
    def _ping(host, timeout=1):
        try:
            r = subprocess.run(["ping", "-c", "1", "-W", str(timeout), host],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _arp_table():
        mapping = {}
        try:
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-f:]{17})", line)
                if m:
                    mapping[m.group(1)] = m.group(2).upper()
        except Exception:
            pass
        return mapping

    # ---- 2) Port tarama + banner ----
    def _scan_host(self, scan, ip, mac, ports):
        open_ports = self._scan_ports(ip, ports)
        real_cves = []
        if scan.mode == "deep" and open_ports and shutil.which("nmap"):
            # GERÇEK pipeline: nmap -sV -> ürün/sürüm/CPE -> NVD -> gerçek CVE
            scan.log(f"[{ip}] nmap -sV çalıştırılıyor (servis+sürüm+CPE tespiti)…")
            real_cves = self._nmap_cve_scan(scan, ip, open_ports)

        # Ağ üzerinden firmware/model parmak izi (HTTP + UPnP)
        firmware = fw.fingerprint_network(ip, open_ports)
        if firmware.get("model") or firmware.get("fw_version"):
            scan.log(f"[{ip}] firmware ipucu: {firmware.get('model','?')} "
                     f"{firmware.get('fw_version','')}".strip(), "info")

        # Cihazdan firmware/config ÇEKMEYİ DENE (deep modda, açık HTTP varsa)
        fw_endpoints = []
        grab_findings = []
        if scan.mode == "deep" and any(p["port"] in (80, 8080, 8000, 81, 443, 8443, 8081, 8888)
                                       for p in open_ports):
            probe = fw.probe_device(ip, open_ports, log=scan.log)
            fw_endpoints = probe["candidates"]
            grab_findings = probe["findings"]

        vendor = self._vendor(mac)
        dtype, icon = self._device_type(open_ports, vendor)
        if scan.mode == "deep":
            # Deep modda bulgular GERÇEK CVE'ler (NVD) + riskli portlar + firmware/config açıkları
            vulns = real_cves + self._risky_ports(open_ports) + grab_findings
        else:
            # Hızlı/Tam modda banner tabanlı hızlı ipuçları
            vulns = self._audit(open_ports)
        risk_score, risk_level, factors = self._risk(open_ports, vulns)
        is_iot = self._is_iot(vendor, open_ports, dtype)
        return {
            "ip": ip, "mac": mac or "-", "vendor": vendor or "Bilinmiyor",
            "device_type": dtype, "icon": icon, "firmware": firmware,
            "fw_endpoints": fw_endpoints,
            "is_iot": is_iot, "open_ports": open_ports, "vulns": vulns,
            "risk_score": risk_score, "risk_level": risk_level,
            "risk_factors": factors,
        }

    def _scan_ports(self, ip, ports, timeout=0.8):
        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
            futs = [ex.submit(self._probe, ip, p, timeout) for p in ports]
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                if r:
                    found.append(r)
        return sorted(found, key=lambda x: x["port"])

    def _probe(self, ip, port, timeout):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) != 0:
                    return None
                banner = self._banner(s, port)
                return {"port": port, "service": COMMON_IOT_PORTS.get(port, ""),
                        "banner": banner, "product": "", "version": "", "cpe": ""}
        except Exception:
            return None

    @staticmethod
    def _banner(sock, port):
        try:
            sock.settimeout(1.5)
            if port in (80, 8080, 443, 8443, 5000, 9000, 49152, 7547):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
            return data.decode(errors="replace").strip()
        except Exception:
            return ""

    def _nmap_cve_scan(self, scan, ip, open_ports):
        """
        GERÇEK zafiyet tespiti (deep mod):
          nmap -sV -oX  ->  her port için ürün/sürüm/CPE
                        ->  NVD API  ->  o sürüme ait GERÇEK CVE'ler
        open_ports kayıtlarını nmap verisiyle (product/version/cpe) zenginleştirir
        ve gerçek CVE listesini döndürür.
        """
        import xml.etree.ElementTree as ET
        cves = []
        try:
            plist = ",".join(str(p["port"]) for p in open_ports)
            xml = subprocess.run(
                ["nmap", "-sV", "--version-all", "-Pn", "-p", plist, "-oX", "-", ip],
                capture_output=True, text=True, timeout=180).stdout
            root = ET.fromstring(xml)
            for portnode in root.iter("port"):
                svc = portnode.find("service")
                if svc is None:
                    continue
                port = int(portnode.get("portid"))
                product = svc.get("product", "")
                version = svc.get("version", "")
                # yalnızca uygulama CPE'leri (cpe:/a:...)
                cpes = [c.text for c in portnode.findall(".//cpe")
                        if c.text and c.text.startswith("cpe:/a")]
                op = next((o for o in open_ports if o["port"] == port), None)
                if op is not None:
                    op["product"] = (product + " " + version).strip()
                    op["version"] = version
                    op["cpe"] = cpes[0] if cpes else ""
                    if product and product not in (op.get("banner") or ""):
                        op["banner"] = (op.get("banner", "") + " | " +
                                        (product + " " + version).strip()).strip(" |")
                    if product:
                        scan.log(f"[{ip}:{port}] nmap → {product} {version}"
                                 + (f"  CPE={cpes[0]}" if cpes else ""))
                # Her CPE için NVD'den gerçek CVE'ler (yalnızca sürüm biliniyorsa)
                for cpe in cpes:
                    if not re.search(r":\d", cpe):   # sürümsüz CPE'yi atla (gürültü)
                        continue
                    scan.log(f"[{ip}:{port}] NVD sorgulanıyor → {cpe}")
                    found = cve.lookup_cpe(cpe, min_cvss=7.0, limit=5)
                    if found:
                        scan.log(f"[{ip}:{port}] NVD: {len(found)} gerçek CVE "
                                 f"(en yüksek CVSS {found[0]['cvss']})", "warn")
                    else:
                        scan.log(f"[{ip}:{port}] NVD: CVSS≥7 CVE yok (güncel/temiz)", "ok")
                    for c in found:
                        cves.append({
                            "port": port, "kind": "cve", "service": product or op.get("service", ""),
                            "version": version, "severity": c["severity"],
                            "cve": c["cve"], "cvss": c["cvss"], "source": "NVD",
                            "vector": c.get("vector", ""), "note": c["desc"] or c.get("vector", ""),
                        })
        except Exception:
            pass
        return cves

    @staticmethod
    def _risky_ports(open_ports):
        """GERÇEK gözlem: açık ve doğası gereği riskli portlar (tahmin değil, ölçüm)."""
        out = []
        for op in open_ports:
            if op["port"] in RISKY_PORTS:
                w, note = RISKY_PORTS[op["port"]]
                sev = "critical" if w >= 8 else "serious" if w >= 6 else "warning"
                out.append({"port": op["port"], "kind": "riskli-port",
                            "service": op.get("service", ""), "version": "",
                            "severity": sev, "cve": "-", "cvss": w,
                            "source": "port-analizi", "note": note})
        return out

    # ---- 3) Parmak izi ----
    @staticmethod
    def _vendor(mac):
        if not mac or mac == "-":
            return None
        return IOT_OUI_PREFIXES.get(mac.upper()[:8])

    @staticmethod
    def _device_type(open_ports, vendor):
        ports = {p["port"] for p in open_ports}
        blob = " ".join((p.get("banner", "") + " " + p.get("product", ""))
                        for p in open_ports).lower()
        ven = (vendor or "").lower()
        for fp in DEVICE_FINGERPRINTS:
            if ports & set(fp.get("any_ports", [])):
                return fp["type"], fp["icon"]
            if any(k in blob for k in fp.get("banner", [])):
                return fp["type"], fp["icon"]
            if any(k in ven for k in fp.get("vendor", [])):
                return fp["type"], fp["icon"]
        return "Genel Cihaz", "DEV"

    @staticmethod
    def _is_iot(vendor, open_ports, dtype):
        if dtype != "Genel Cihaz":
            return True
        if vendor:
            return True
        iot_ports = {23, 554, 1883, 5683, 8883, 6668, 7547, 37777, 34567, 1900}
        return bool({p["port"] for p in open_ports} & iot_ports)

    # ---- 4) Denetim: eski sürüm + riskli port ----
    @staticmethod
    def _extract_versions(text):
        out = []
        patterns = [
            (r"OpenSSH[_/](\d+\.\d+[\w.]*)", "openssh"),
            (r"dropbear[_ /]?(\d{4}\.\d+)", "dropbear"),
            (r"Apache/(\d+\.\d+\.\d+)", "apache"),
            (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
            (r"lighttpd/(\d+\.\d+\.\d+)", "lighttpd"),
            (r"GoAhead", "goahead"),
            (r"Boa/(\d+\.\d+[\w.]*)", "boa"),
            (r"BusyBox[ v]*(\d+\.\d+\.\d+)", "busybox"),
            (r"vsftpd (\d+\.\d+\.\d+)", "vsftpd"),
            (r"mosquitto[ /]?(\d+\.\d+\.\d+)", "mosquitto"),
            (r"miniupnpd[/ ]?(\d+\.\d+[\w.]*)", "miniupnpd"),
            (r"hostapd[/ ]?(\d+\.\d+[\w.]*)", "hostapd"),
        ]
        for pat, svc in patterns:
            m = re.search(pat, text or "", re.IGNORECASE)
            if m:
                out.append((svc, m.group(1) if m.lastindex else None))
        return out

    def _audit(self, open_ports):
        vulns = []
        # a) eski sürüm bulguları
        for op in open_ports:
            text = (op.get("banner", "") + " " + op.get("product", ""))
            for svc, ver in self._extract_versions(text):
                for sig in KNOWN_OUTDATED:
                    if sig["service"] != svc:
                        continue
                    if ver is None:
                        vulns.append(self._vuln(op["port"], svc, "bilinmiyor",
                                     "medium", sig, "Sürüm okunamadı; elle doğrulayın."))
                    elif version_less_than(ver, sig["bad_below"]):
                        sev = "critical" if sig["cvss"] >= 9 else "serious" if sig["cvss"] >= 7 else "medium"
                        vulns.append(self._vuln(op["port"], svc, ver, sev, sig,
                                     f"{svc} {ver} < güvenli {sig['bad_below']}."))
        # b) riskli port bulguları
        for op in open_ports:
            if op["port"] in RISKY_PORTS:
                w, note = RISKY_PORTS[op["port"]]
                sev = "critical" if w >= 8 else "serious" if w >= 6 else "warning"
                vulns.append({"port": op["port"], "kind": "riskli-port",
                              "service": op.get("service", ""), "version": "",
                              "severity": sev, "cve": "-", "cvss": w,
                              "note": note})
        return vulns

    @staticmethod
    def _vuln(port, svc, ver, sev, sig, extra):
        return {"port": port, "kind": "eski-sürüm", "service": svc, "version": ver,
                "severity": sev, "cve": sig["cve"], "cvss": sig["cvss"],
                "note": f"{extra} {sig['note']}"}

    # ---- 5) Risk skoru (0-100) ----
    @staticmethod
    def _risk(open_ports, vulns):
        score = 0.0
        factors = []
        for v in vulns:
            contrib = v.get("cvss", 5) * (2.2 if v["severity"] == "critical" else
                                          1.6 if v["severity"] == "serious" else 1.0)
            score += contrib
            desc = v.get("note") or v.get("detail") or v.get("title") or ""
            factors.append(f"{v.get('service') or v.get('port','')}: {desc[:60]}")
        # şifreli alternatifi olmayan açık yönetim portları küçük ek risk
        ports = {p["port"] for p in open_ports}
        if 80 in ports and 443 not in ports:
            score += 3
            factors.append("Web arayüzü yalnızca HTTP (şifresiz).")
        score = min(100, round(score, 1))
        level = ("critical" if score >= 60 else "serious" if score >= 35
                 else "warning" if score >= 10 else "good")
        return score, level, factors
