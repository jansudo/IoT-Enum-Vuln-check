#!/usr/bin/env python3
"""
app.py — IoT Güvenlik Tarayıcısı web sunucusu (Flask + SSE)
===========================================================
Canlı, tarayıcı tabanlı bir kontrol paneli sunar. Tarama arka planda çalışır;
sonuçlar Server-Sent Events (SSE) ile arayüze anlık akar.

Çalıştırma:
    cd iot-scanner
    python3 app.py            # http://127.0.0.1:5000
    python3 app.py --port 8000

ETİK: Yalnızca kendi/izinli ağınızda kullanın.
"""

import argparse
import json
import os
import queue
import tempfile
import threading
import time
from datetime import datetime

from flask import Flask, Response, request, jsonify, send_from_directory

from scanner import ScanEngine
from scanner import firmware as fw

app = Flask(__name__, static_folder="web", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 450 * 1024 * 1024   # firmware yüklemesi için
engine = ScanEngine()


# --------------------------------------------------------------------------- #
# Firmware analiz işi (canlı loglu, arka plan thread)
# --------------------------------------------------------------------------- #
class FirmwareJob:
    def __init__(self, name):
        self.name = name
        self.state = "çalışıyor"
        self.log = []
        self.result = None
        self.q = queue.Queue()
        self.started = datetime.now().isoformat(timespec="seconds")

    def emit(self, msg, level="info"):
        rec = {"level": level, "time": datetime.now().strftime("%H:%M:%S"), "msg": msg}
        self.log.append(rec)
        self.q.put({"kind": "log", **rec})


fw_current = None
fetch_current = None
fw_lock = threading.Lock()

DOWNLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads")


@app.route("/")
def index():
    return send_from_directory("web", "index.html")


@app.route("/api/network")
def api_network():
    """Otomatik tespit edilen yerel ağı döndürür."""
    return jsonify({"network": engine.detect_network()})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Yeni tarama başlatır."""
    data = request.get_json(force=True, silent=True) or {}
    network = data.get("network") or engine.detect_network()
    mode = data.get("mode", "quick")
    if mode not in ("quick", "full", "deep", "demo"):
        mode = "quick"
    scan = engine.start(network, mode)
    return jsonify({"id": scan.id, "network": scan.network, "mode": scan.mode,
                    "state": scan.state})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    if engine.current:
        engine.current.stop()
    return jsonify({"ok": True})


@app.route("/api/status")
def api_status():
    """Anlık durum (SSE'siz istemciler / sayfa yenileme için)."""
    if not engine.current:
        return jsonify({"state": "hazır", "devices": [], "summary": {}})
    return jsonify(engine.current.snapshot())


@app.route("/api/export")
def api_export():
    """Son taramayı JSON rapor olarak indirir."""
    if not engine.current:
        return jsonify({"error": "tarama yok"}), 404
    snap = engine.current.snapshot()
    body = json.dumps(snap, ensure_ascii=False, indent=2)
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition":
                             f'attachment; filename=iot-rapor-{snap["id"]}.json'})


@app.route("/api/firmware", methods=["POST"])
def api_firmware():
    """Firmware imajı analizi başlatır. Dosya yükleme VEYA sunucudaki bir yol."""
    global fw_current
    with fw_lock:
        if fw_current and fw_current.state == "çalışıyor":
            return jsonify({"error": "zaten bir analiz çalışıyor"}), 409

    path, name, tmp = None, "", False
    if "file" in request.files and request.files["file"].filename:
        up = request.files["file"]
        name = os.path.basename(up.filename)
        fd, path = tempfile.mkstemp(suffix="_" + name)
        os.close(fd)
        up.save(path)
        tmp = True
    else:
        data = request.get_json(force=True, silent=True) or {}
        path = data.get("path", "").strip()
        name = os.path.basename(path) if path else ""
        if not path or not os.path.isfile(path):
            return jsonify({"error": "Dosya bulunamadı: " + str(path)}), 400

    job = FirmwareJob(name or "firmware")
    with fw_lock:
        fw_current = job

    def run():
        try:
            job.result = fw.analyze(path, log=job.emit)
        except Exception as e:  # noqa
            job.emit(f"HATA: {e}", "warn")
            job.result = {"ok": False, "error": str(e)}
        finally:
            job.state = "bitti"
            job.q.put({"kind": "done", "result": job.result})
            if tmp:
                try:
                    os.unlink(path)
                except Exception:
                    pass

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"ok": True, "name": job.name})


@app.route("/api/firmware/fetch", methods=["POST"])
def api_firmware_fetch():
    """Bir URL'den firmware imajını indirir (arka planda, canlı loglu)."""
    global fetch_current
    with fw_lock:
        if fetch_current and fetch_current.state == "çalışıyor":
            return jsonify({"error": "zaten bir indirme çalışıyor"}), 409
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL gerekli"}), 400

    job = FirmwareJob("indirme")
    with fw_lock:
        fetch_current = job

    def run():
        try:
            job.result = fw.fetch_url(url, DOWNLOAD_DIR, log=job.emit)
        except Exception as e:  # noqa
            job.emit(f"HATA: {e}", "warn")
            job.result = {"ok": False, "error": str(e)}
        finally:
            job.state = "bitti"
            job.q.put({"kind": "done", "result": job.result})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/firmware/fetch/stream")
def api_firmware_fetch_stream():
    job = fetch_current
    if not job:
        return Response("event: idle\ndata: {}\n\n", mimetype="text/event-stream")

    def gen():
        for rec in list(job.log):
            yield _sse("log", rec)
        if job.state == "bitti":
            yield _sse("done", {"result": job.result})
            return
        while True:
            try:
                ev = job.q.get(timeout=15)
            except queue.Empty:
                yield ": keep-alive\n\n"
                if job.state == "bitti":
                    break
                continue
            yield _sse(ev["kind"], ev)
            if ev["kind"] == "done":
                break

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/firmware/grab", methods=["POST"])
def api_firmware_grab():
    """Taranan bir cihazdan firmware/config çekmeyi dener (canlı loglu)."""
    global fetch_current
    with fw_lock:
        if fetch_current and fetch_current.state == "çalışıyor":
            return jsonify({"error": "zaten bir indirme/çekme çalışıyor"}), 409
    data = request.get_json(force=True, silent=True) or {}
    ip = (data.get("ip") or "").strip()
    # cihazın açık portlarını mevcut taramadan bul
    open_ports = None
    if engine.current:
        for d in engine.current.snapshot()["devices"]:
            if d["ip"] == ip:
                open_ports = d["open_ports"]
                break
    if open_ports is None:
        # tarama yoksa yaygın HTTP portlarını dene
        open_ports = [{"port": p} for p in (80, 8080, 443, 8443, 81, 8000)]
    if not ip:
        return jsonify({"error": "ip gerekli"}), 400

    job = FirmwareJob("cihazdan çekme")
    with fw_lock:
        fetch_current = job

    def run():
        try:
            job.result = fw.grab_from_device(ip, open_ports, DOWNLOAD_DIR, log=job.emit)
        except Exception as e:  # noqa
            job.emit(f"HATA: {e}", "warn")
            job.result = {"saved": [], "findings": [], "error": str(e)}
        finally:
            job.state = "bitti"
            job.q.put({"kind": "done", "result": job.result})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/firmware/download")
def api_firmware_download():
    """İndirilen firmware .bin dosyasını kullanıcının tarayıcısına sunar."""
    name = os.path.basename(request.args.get("name", ""))
    if not name or not os.path.isfile(os.path.join(DOWNLOAD_DIR, name)):
        return jsonify({"error": "dosya yok"}), 404
    return send_from_directory(DOWNLOAD_DIR, name, as_attachment=True,
                               mimetype="application/octet-stream")


@app.route("/api/firmware/status")
def api_firmware_status():
    if not fw_current:
        return jsonify({"state": "hazır", "log": [], "result": None})
    return jsonify({"state": fw_current.state, "name": fw_current.name,
                    "log": fw_current.log, "result": fw_current.result})


@app.route("/api/firmware/stream")
def api_firmware_stream():
    job = fw_current
    if not job:
        return Response("event: idle\ndata: {}\n\n", mimetype="text/event-stream")

    def gen():
        # geçmiş loglar
        for rec in list(job.log):
            yield _sse("log", rec)
        if job.state == "bitti":
            yield _sse("done", {"result": job.result})
            return
        while True:
            try:
                ev = job.q.get(timeout=15)
            except queue.Empty:
                yield ": keep-alive\n\n"
                if job.state == "bitti":
                    break
                continue
            yield _sse(ev["kind"], ev)
            if ev["kind"] == "done":
                break

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/stream")
def api_stream():
    """SSE: canlı tarama olayları akışı."""
    scan = engine.current
    if not scan:
        return Response("event: idle\ndata: {}\n\n", mimetype="text/event-stream")

    def gen():
        # İlk olarak mevcut anlık görüntüyü gönder (geç bağlanan istemciler için)
        yield _sse("snapshot", scan.snapshot())
        q = scan.events()
        while True:
            try:
                ev = q.get(timeout=15)
            except queue.Empty:
                yield ": keep-alive\n\n"
                if scan.state in ("bitti", "hata", "durduruldu"):
                    break
                continue
            yield _sse(ev["kind"], ev)
            if ev["kind"] == "done":
                break

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="IoT Güvenlik Tarayıcısı web sunucusu")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    print(f"""
  ┌───────────────────────────────────────────────┐
  │   IoT Güvenlik Tarayıcısı — Web Kontrol Paneli  │
  │   Tarayıcıda aç:  http://{args.host}:{args.port}        │
  │   Durdurmak için: Ctrl+C                        │
  │   Yalnızca izinli/kendi ağınızda kullanın.      │
  └───────────────────────────────────────────────┘
""")
    # threaded=True: SSE + tarama aynı anda çalışsın
    app.run(host=args.host, port=args.port, threaded=True, debug=False)
