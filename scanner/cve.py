"""
cve.py
======
GERÇEK zafiyet verisi. Kendi elle yazılmış listeye DEĞİL, resmi NVD (NIST National
Vulnerability Database) API'sine ve yedek olarak CIRCL CVE-Search'e sorgu atar.

Akış:
  nmap -sV  →  servisin CPE'si (ör. cpe:/a:openbsd:openssh:7.4)
            →  NVD API  →  o sürüme ait GERÇEK CVE'ler + GERÇEK CVSS puanları

- İnternet gerektirir (bu, gerçek zafiyet taramasının doğası).
- Sonuçlar CPE bazında önbelleğe alınır (aynı sürüm tekrar sorgulanmaz).
- NVD hız limiti: anahtarsız ~5 istek/30 sn. NVD_API_KEY ortam değişkeni
  tanımlıysa limit ~50/30 sn'ye çıkar ve otomatik kullanılır.

Kaynak: https://services.nvd.nist.gov/rest/json/cves/2.0
"""

import json
import os
import threading
import time
import urllib.parse
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_URL = "https://cve.circl.lu/api/search"
API_KEY = os.environ.get("NVD_API_KEY", "").strip()

_cache = {}                 # cpe -> [cve,...]
_cache_lock = threading.Lock()
_rate_lock = threading.Lock()
_last_call = [0.0]


def _throttle():
    """NVD hız limitine uymak için istekler arası minimum aralık."""
    with _rate_lock:
        min_gap = 0.7 if API_KEY else 6.5   # anahtarsızken güvenli aralık
        wait = min_gap - (time.time() - _last_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_call[0] = time.time()


def _http_json(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "iot-scanner-edu/1.0"})
    if API_KEY:
        req.add_header("apiKey", API_KEY)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode(errors="replace"))


def _severity(score):
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "serious"
    if score >= 4.0:
        return "warning"
    return "good"


def _parse_nvd(data, min_cvss):
    out = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        cid = c.get("id")
        metrics = c.get("metrics", {})
        score, vector = None, ""
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if k in metrics and metrics[k]:
                cd = metrics[k][0]["cvssData"]
                score = cd.get("baseScore")
                vector = cd.get("vectorString", "")
                break
        if score is None or score < min_cvss:
            continue
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", ""); break
        out.append({"cve": cid, "cvss": score, "severity": _severity(score),
                    "vector": vector, "desc": desc[:400]})
    out.sort(key=lambda x: -x["cvss"])
    return out


def lookup_cpe(cpe, min_cvss=7.0, limit=5):
    """
    Bir CPE için GERÇEK CVE listesi döndürür (NVD, yedek CIRCL).
    cpe örn: 'cpe:/a:openbsd:openssh:7.4' veya 'cpe:2.3:a:openbsd:openssh:7.4:...'
    """
    if not cpe:
        return []
    key = (cpe, min_cvss)
    with _cache_lock:
        if key in _cache:
            return _cache[key]

    # CPE'yi 2.3 biçimine normalize et (NVD virtualMatchString için)
    match = _to_cpe23(cpe)
    result = []
    try:
        _throttle()
        url = (NVD_URL + "?virtualMatchString=" +
               urllib.parse.quote(match) + "&resultsPerPage=50")
        data = _http_json(url)
        result = _parse_nvd(data, min_cvss)[:limit]
    except Exception:
        # Yedek: CIRCL CVE-Search
        try:
            result = _circl_fallback(cpe, min_cvss, limit)
        except Exception:
            result = []

    with _cache_lock:
        _cache[key] = result
    return result


def _to_cpe23(cpe):
    """cpe:/a:vendor:product:version  ->  cpe:2.3:a:vendor:product:version"""
    if cpe.startswith("cpe:2.3:"):
        return ":".join(cpe.split(":")[:6])   # part:vendor:product:version yeter
    if cpe.startswith("cpe:/"):
        body = cpe[len("cpe:/"):]              # a:vendor:product:version:...
        parts = body.split(":")
        return "cpe:2.3:" + ":".join(parts[:4])
    return cpe


def _circl_fallback(cpe, min_cvss, limit):
    """NVD erişilemezse CIRCL üzerinden vendor/product ile ara."""
    parts = _to_cpe23(cpe).split(":")
    if len(parts) < 5:
        return []
    vendor, product = parts[3], parts[4]
    data = _http_json(f"{CIRCL_URL}/{vendor}/{product}", timeout=20)
    rows = data.get("results", data) if isinstance(data, dict) else data
    out = []
    for c in (rows or [])[:60]:
        score = c.get("cvss")
        try:
            score = float(score) if score is not None else None
        except Exception:
            score = None
        if score is None or score < min_cvss:
            continue
        out.append({"cve": c.get("id") or c.get("aliases", [""])[0],
                    "cvss": score, "severity": _severity(score),
                    "vector": "", "desc": (c.get("summary") or "")[:200]})
    out.sort(key=lambda x: -(x["cvss"] or 0))
    return out[:limit]


def online():
    """İnternet / NVD erişilebilir mi (arayüzde uyarı için)."""
    try:
        _http_json(NVD_URL + "?resultsPerPage=1", timeout=8)
        return True
    except Exception:
        return False
