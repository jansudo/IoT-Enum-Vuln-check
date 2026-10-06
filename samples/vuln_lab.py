#!/usr/bin/env python3
"""
vuln_lab.py - Sanal Zafiyetli IoT Ag Laboratuvari
==================================================
Kendi gercek agini taramak yerine, bu script loopback (127.0.0.x) uzerinde
BILEREK ZAFIYETLI 5 sahte IoT cihazi ayaga kaldirir. Sonra IoT tarayicini
127.0.0.0/29 agina yonlendirip guvenle tarama yaparsin.

  - Sudo / root GEREKMEZ (yuksek portlar: 8080, 2323, 1883, 37777, 34567...)
  - Dis dunyaya acilmaz; her sey loopback'te kalir (zararsiz).
  - Sahte servisler GERCEK eski surum basliklari dondurur -> nmap gercek CPE
    uretir -> NVD gercek CVE verir. Ayrica korumasiz /rom-0, /System/... gibi
    firmware/config uc noktalari iceri gomulu sirlarla sunulur.

Calistir:
    python3 samples/vuln_lab.py          # Ctrl+C ile durdur

Sonra tarayicida (http://127.0.0.1:5000):
    Ag:  127.0.0.0/29      Mod: Gercek CVE (nmap + NVD)  ya da  Hizli
"""

import http.server
import os
import socket
import threading
import time

ROM0 = (b"\x00ROUTERCFG\x00\n"
        b"admin_password=admin1234\n"
        b"wifi_ssid=EvAgi_2G\nwifi_key=S3cretWiFiKey!\n"
        b"ppp_username=user@isp\nppp_password=isppass2019\n"
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEoFAKEkeyForClassDemoOnly0000\n-----END RSA PRIVATE KEY-----\n"
        + os.urandom(600))

HIK_CFG = (b"\x00HIKCONFIG\x00\n"
           b"<userName>admin</userName><password>12345</password>\n"
           b"<macAddress>44:19:b6:aa:bb:cc</macAddress>\n"
           b"firmware=V5.4.0 build 160530\n" + os.urandom(500))

DEVICES = {
    "127.0.0.2": {
        "name": "Ev Yonlendiricisi",
        "http": {8080: ("lighttpd/1.4.28", "Router Login - RT-AC51",
                        {"/rom-0": ("application/octet-stream", ROM0)})},
        "tcp": {2323: b"\xff\xfb\x01login: "},
    },
    "127.0.0.3": {
        "name": "IP Kamera",
        "http": {8080: ("GoAhead-Webs", "NETSurveillance WEB - IP Camera",
                        {"/System/configurationFile": ("application/octet-stream", HIK_CFG)})},
        "tcp": {37777: b"\xa0\x00\x00\x60dahua-dvr"},
    },
    "127.0.0.4": {
        "name": "Akilli Ev Hub",
        "http": {8080: ("Boa/0.94.13", "SmartHome Gateway", {})},
        "tcp": {1883: b"\x20\x02\x00\x00"},
    },
    "127.0.0.5": {
        "name": "DVR Kayit Cihazi",
        "http": {8080: ("Apache/2.4.29 (Unix)", "DVR Web Client", {})},
        "tcp": {34567: b"\xff\x00\x00\x00xiongmai-dvr",
                2323: b"\xff\xfb\x01login: "},
    },
    "127.0.0.6": {
        "name": "Ag Depolama (NAS)",
        "http": {8080: ("nginx/1.14.0", "NAS Yonetim Paneli",
                        {"/backup.bin": ("application/octet-stream",
                                         b"\x00NASBACKUP\x00 root:$1$abc$0123456789hashed:0:0::/root:/bin/sh\n"
                                         + os.urandom(400))})},
        "tcp": {},
    },
}

_servers = []


def make_http_handler(server_header, title, paths):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        server_version = server_header
        sys_version = ""
        def version_string(self):
            return server_header
        def handle_one_request(self):
            try:
                super().handle_one_request()
            except Exception:
                self.close_connection = True
        def log_message(self, *a):
            pass
        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass
        def do_GET(self):
            if self.path in paths:
                ctype, body = paths[self.path]
                self._send(200, ctype, body)
            else:
                page = ("<html><head><title>%s</title></head><body>"
                        "<h1>%s</h1><p>Yetkili erisim gerektirir.</p></body></html>"
                        % (title, title)).encode()
                self._send(200, "text/html", page)
        def do_HEAD(self):
            self.do_GET()
    return Handler


def start_http(ip, port, server_header, title, paths):
    try:
        httpd = http.server.HTTPServer((ip, port), make_http_handler(server_header, title, paths))
        _servers.append(httpd)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return True
    except Exception as e:
        print("  [!] HTTP %s:%d baslatilamadi: %s" % (ip, port, e))
        return False


def start_tcp_banner(ip, port, banner):
    def serve():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((ip, port))
            s.listen(16)
        except Exception as e:
            print("  [!] TCP %s:%d baslatilamadi: %s" % (ip, port, e))
            return
        _servers.append(s)
        while True:
            try:
                c, _ = s.accept()
            except Exception:
                break
            try:
                c.sendall(banner)
                c.settimeout(3)
                try:
                    c.recv(64)
                except Exception:
                    pass
            except Exception:
                pass
            finally:
                try:
                    c.close()
                except Exception:
                    pass
    threading.Thread(target=serve, daemon=True).start()


def main():
    print("")
    print("  === Sanal Zafiyetli IoT Laboratuvari ===")
    print("  Loopback (127.0.0.x) - zararsiz, disa kapali")
    print("")
    count = 0
    for ip, dev in DEVICES.items():
        started = []
        for port, (hdr, title, paths) in dev.get("http", {}).items():
            if start_http(ip, port, hdr, title, paths):
                started.append("HTTP:%d (%s)" % (port, hdr))
        for port, banner in dev.get("tcp", {}).items():
            start_tcp_banner(ip, port, banner)
            started.append("TCP:%d" % port)
        count += 1
        print("  [+] %-14s %-20s  %s" % (ip, dev["name"], ", ".join(started)))
    print("")
    print("  %d cihaz calisiyor.  Tarayicida (http://127.0.0.1:5000):" % count)
    print("      Ag:  127.0.0.0/29")
    print("      Mod: 'Gercek CVE (nmap + NVD)'  veya  'Hizli'")
    print("  Durdurmak icin: Ctrl+C")
    print("")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n  Lab durduruldu.")


if __name__ == "__main__":
    main()
