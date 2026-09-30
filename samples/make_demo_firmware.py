#!/usr/bin/env python3
"""
make_demo_firmware.py
---------------------
Sunum/deneme için GERÇEKÇİ ama ZARARSIZ bir örnek IoT firmware imajı üretir.
İçine bilerek eski bileşenler ve klasik güvenlik hataları gömülür; böylece
'Firmware Analizi' bölümü gerçek bulgular (Heartbleed dahil gerçek CVE'ler,
gömülü SquashFS, sabit-kodlu parola/anahtar) gösterir.

Bu imaj çalıştırılabilir bir firmware DEĞİLDİR — sadece analiz aracını
beslemek için imza + string içeren bir demodur.

    python3 make_demo_firmware.py           # -> demo_firmware.bin
"""
import os
import sys

def build():
    b = bytearray()
    b += b"\x27\x05\x19\x56"                                  # U-Boot uImage magic
    b += b"U-Boot 2010.09 (IoT-CAM bootloader)\n"
    b += b"hsqs" + b"\x00" * 60                               # SquashFS magic
    b += b"/etc /bin /www squashfs-root filesystem\n"
    # bilerek ESKİ bileşenler (gerçek CVE'ler için)
    b += b"BusyBox v1.19.4 (2013-03-14 12:00:00) multi-call binary\n"
    b += b"Dropbear SSH server 2015.71\n"
    b += b"OpenSSL 1.0.1e 11 Feb 2013\n"                      # <- Heartbleed (CVE-2014-0160)
    b += b"lighttpd/1.4.28 (ssl)\n"
    b += b"dnsmasq-2.72\n"
    # klasik firmware güvenlik hataları
    b += b"root:x:0:0:root:/root:/bin/sh\n"
    b += b"admin:$1$saltsalt$3xamPleHashValue012345:0:0:admin:/:/bin/sh\n"
    b += b"telnetd -l /bin/login -p 23\n"
    b += b"default_password=admin1234\n"
    b += b"api_key=AKIAEXAMPLE1234567890\n"
    b += b"http://firmware.example-iot.com/update/latest.bin\n"
    b += (b"-----BEGIN RSA PRIVATE KEY-----\n"
          b"MIIEowIBAAKCAQEA0demoKeyDoNotUseThisIsFakeForClassDemoOnly0000000\n"
          b"-----END RSA PRIVATE KEY-----\n")
    b += b"nvram set lan_ipaddr=192.168.1.1\n"
    # biraz 'gerçekçi' rastgele veri (dosyayı büyütür)
    b += os.urandom(64 * 1024)
    return bytes(b)

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "demo_firmware.bin")
    open(out, "wb").write(build())
    print("Örnek firmware yazıldı:", out, f"({os.path.getsize(out):,} bayt)")
    print("Arayüzde 'Firmware Analizi' bölümüne bu dosyayı sürükle.")
