"""Coordinate-driven signal-intelligence core for WireTapper.

Every public function in this module takes a latitude/longitude (plus an
optional radius in kilometres) and returns plain dictionaries.  There is no
Flask dependency, so the exact same engine powers:

* the web UI (``app.py``)
* the terminal CLI and the interactive chat REPL (``cli.py``)
* the test-suite (``tests/test_sigint.py``)

Design rules
------------
1. **No synthesised data.**  If a source has no API key, is unreachable or
   simply returns nothing, the envelope says so through ``status``/``detail``.
   Nothing is ever padded with random coordinates.
2. **Uniform envelope.**  Every source call returns::

       {"source": str,
        "status": "ok" | "empty" | "skipped" | "error",
        "detail": str,
        "count": int,
        "devices": [ {...}, ... ]}

3. **Distance everywhere.**  Every device carries ``distance_km`` relative to
   the query point, so results stay useful in a text/chat window with no map.
"""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests

import flock_manager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "credentials.db")
ENV_PATH = os.path.join(BASE_DIR, ".env")

USER_AGENT = "WireTapper-SignalIntelligence/1.0"
DEFAULT_TIMEOUT = 15

# Values that mean "the user never configured this key".
PLACEHOLDERS = {
    "WIGLE_API_NAME": "your_wigle_api_name",
    "WIGLE_API_TOKEN": "your_wigle_api_token",
    "OPENCELLID_API_KEY": "your_opencellid_api_key",
    "SHODAN_API_KEY": "your_shodan_api_key",
    "CENSYS_API_ID": "your_censys_api_id",
    "CENSYS_API_SECRET": "your_censys_api_secret",
}

# Modes accepted by :func:`scan`.
MODES = ("wifi", "bluetooth", "cell", "iot", "flock", "sdr")


# --------------------------------------------------------------------------- #
# Geo helpers
# --------------------------------------------------------------------------- #
def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points, in kilometres."""
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def bounding_box(lat: float, lon: float, radius_km: float):
    """Return ``(lat_min, lat_max, lon_min, lon_max)`` for a radius around a point.

    Longitude degrees are corrected for latitude so a "2 km" box really is
    ~2 km wide at any place on Earth (important at northern latitudes).
    """
    radius_km = max(float(radius_km), 0.01)
    dlat = radius_km / 111.0
    cos_lat = math.cos(math.radians(lat))
    dlon = radius_km / (111.0 * cos_lat) if cos_lat > 1e-6 else 360.0
    return lat - dlat, lat + dlat, lon - dlon, lon + dlon


def bbox_string(lat: float, lon: float, radius_km: float) -> str:
    """WiGLE-style ``latrange/longrange`` helper, rendered as one string."""
    lat_min, lat_max, lon_min, lon_max = bounding_box(lat, lon, radius_km)
    return f"{lat_min:.6f},{lat_max:.6f},{lon_min:.6f},{lon_max:.6f}"


def _f(value, default=None):
    """Tolerant float cast (WiGLE/CSV values arrive as strings, '', None, '?')."""
    if value is None:
        return default
    try:
        text = str(value).strip()
        if not text or text in {"?", "-", "None"}:
            return default
        return float(text)
    except (TypeError, ValueError):
        return default


def envelope(source, status, detail="", devices=None):
    devices = devices or []
    return {
        "source": source,
        "status": status,
        "detail": detail,
        "count": len(devices),
        "devices": devices,
    }


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #
class Credentials:
    """Read-only view of the WireTapper API keys.

    Lookup precedence (highest first):

    1. ``credentials.db`` (SQLite) — what the web UI writes to
    2. ``.env`` next to this file
    3. process environment variables

    Placeholder values from ``PLACEHOLDERS`` are treated as "not configured".
    """

    KEYS = tuple(PLACEHOLDERS)

    def __init__(self, db_path: str = DB_PATH, env_path: str = ENV_PATH):
        self.db_path = db_path
        self.env_path = env_path
        self._values = {}
        self._origins = {}
        self._load()

    # -- loading ---------------------------------------------------------- #
    def _load(self):
        for key in self.KEYS:
            value, origin = self._from_db(key)
            if value is None:
                value, origin = self._from_env_file(key)
            if value is None:
                value, origin = self._from_os_env(key)
            if value and value.strip() and value.strip() != PLACEHOLDERS[key]:
                self._values[key] = value.strip()
                self._origins[key] = origin

    def _from_db(self, key):
        if not os.path.exists(self.db_path):
            return None, None
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT value FROM credentials WHERE key = ?", (key,)
                ).fetchone()
            if row and row[0]:
                return str(row[0]), "credentials.db"
        except sqlite3.Error:
            pass
        return None, None

    def _from_env_file(self, key):
        if not os.path.exists(self.env_path):
            return None, None
        try:
            with open(self.env_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    name, value = line.split("=", 1)
                    if name.strip() == key and value.strip():
                        return value.strip(), ".env"
        except OSError:
            pass
        return None, None

    def _from_os_env(self, key):
        value = os.environ.get(key)
        if value and value.strip():
            return value.strip(), "environment"
        return None, None

    # -- public API ------------------------------------------------------- #
    def get(self, key: str, default: str = "") -> str:
        return self._values.get(key, default)

    def has(self, key: str) -> bool:
        return key in self._values

    def wigle_ready(self) -> bool:
        return self.has("WIGLE_API_NAME") and self.has("WIGLE_API_TOKEN")

    def origin(self, key: str) -> str:
        return self._origins.get(key, "not configured")

    @staticmethod
    def mask(value: str) -> str:
        if not value:
            return "-"
        if len(value) <= 8:
            return value[0] + "*" * (len(value) - 1)
        return f"{value[:4]}{'*' * 6}{value[-2:]} (len {len(value)})"

    def report(self):
        """Per-key status for ``config show`` — never prints a full secret."""
        rows = []
        for key in self.KEYS:
            value = self._values.get(key)
            rows.append(
                {
                    "key": key,
                    "configured": bool(value),
                    "origin": self.origin(key),
                    "masked": self.mask(value) if value else "-",
                }
            )
        return rows


# --------------------------------------------------------------------------- #
# Device classification (shared with the web UI)
# --------------------------------------------------------------------------- #
_RULES = (
    ("sdr", ("SDR", "RTL-SDR", "HACKRF", "ADSB", "SUBGHZ", "RF_BEACON", "HAM_RADIO",
             "RADIO", "433MHZ", "868MHZ", "915MHZ")),
    ("car", ("CAR", "FORD", "TOYOTA", "BMW", "TESLA", "SYNC", "MAZDA", "HONDA",
             "UCONNECT", "HYUNDAI", "LEXUS", "NISSAN")),
    ("tv", ("TV", "BRAVIA", "VIZIO", "SAMSUNG", "LG", "ROKU", "FIRE", "SMARTVIEW", "KDL-")),
    ("headphone", ("HEADPHONE", "EARBUD", "BOSE", "SONY", "BEATS", "AUDIO", "AIRPOD",
                   "JBL", "SENNHEISER")),
    ("dashcam", ("DASHCAM", "DASH CAM", "DVR", "70MAI", "VIOFO", "GARMIN DASH")),
    ("camera", ("CAM", "SURVEILLANCE", "SECURITY", "NEST", "RING", "ARLO", "HIKVISION",
                "DAHUA", "REOLINK")),
    ("iot", ("WATCH", "FITBIT", "GARMIN", "WHOOP")),
)


def classify_device(name, default_type: str) -> str:
    """Heuristic device-type guess from a SSID/product banner."""
    if not name:
        return default_type
    upper = str(name).upper()
    for dev_type, keywords in _RULES:
        if any(k in upper for k in keywords):
            return dev_type
    return default_type


# --------------------------------------------------------------------------- #
# USB SDR hardware detection (offline, no network)
# --------------------------------------------------------------------------- #
_SDR_SIGNATURES = (
    (("0bda", ("2838", "2832")), "rtl", "RTL2838UHIDIR RTL-SDR Blog V4", "500 kHz - 1766 MHz"),
    (("1d50", ("6089", "604b")), "hackrf", "Great Scott Gadgets HackRF One", "1 MHz - 6 GHz"),
    (("1d50", ("60a1",)), "airspy", "Airspy R2 / Mini", "24 MHz - 1800 MHz"),
)


def detect_sdr(usb_dir: str = "/sys/bus/usb/devices") -> dict:
    """Detect an attached RTL-SDR / HackRF / Airspy dongle via sysfs.

    Returns hardware facts only.  Detecting a dongle is *not* the same as
    receiving a signal — no RF data is invented here.
    """
    result = {
        "connected": False,
        "device": "No SDR Device Detected",
        "frequency_range": None,
        "status": "Disconnected",
        "detail": "No matching USB vendor:product ID found",
    }

    if not os.path.isdir(usb_dir):
        result["detail"] = f"{usb_dir} not available on this platform"
        return result

    try:
        entries = sorted(os.listdir(usb_dir))
    except OSError as exc:
        result["detail"] = f"USB enumeration failed: {exc}"
        return result

    for dev in entries:
        dev_path = os.path.join(usb_dir, dev)
        product = _read_file(os.path.join(dev_path, "product")).lower()
        vendor = _read_file(os.path.join(dev_path, "idVendor")).lower()
        product_id = _read_file(os.path.join(dev_path, "idProduct")).lower()

        for (sig_vendor, sig_products), name_hint, fallback_name, freq in _SDR_SIGNATURES:
            if (vendor == sig_vendor and product_id in sig_products) or name_hint in product:
                result.update(
                    {
                        "connected": True,
                        "device": _read_file(os.path.join(dev_path, "product")) or fallback_name,
                        "frequency_range": freq,
                        "status": "Active Hardware Link",
                        "detail": f"Matched USB {vendor}:{product_id} at {dev}",
                    }
                )
                return result

        if "sdr" in product or "software defined radio" in product:
            result.update(
                {
                    "connected": True,
                    "device": _read_file(os.path.join(dev_path, "product")),
                    "frequency_range": "unknown (unrecognised SDR descriptor)",
                    "status": "Active Hardware Link",
                    "detail": f"Generic SDR descriptor at {dev}",
                }
            )
            return result

    return result


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _sdr_probe() -> dict:
    """SDR mode: report the attached receiver hardware — never invented signals.

    A dongle being present is a hardware fact; the RF spectrum it could see is
    not captured by WireTapper, so the device list stays empty and the status
    text says exactly that.
    """
    info = detect_sdr()
    detail = f"{info['device']} · {info['detail']}"
    if info.get("frequency_range"):
        detail += f" · tuning range {info['frequency_range']}"
    detail += " · no RF capture performed"
    env = envelope("sdr", "ok" if info["connected"] else "empty", detail, [])
    env["sdr_status"] = info
    return env


# --------------------------------------------------------------------------- #
# Geocoding (OpenStreetMap Nominatim)
# --------------------------------------------------------------------------- #
def geocode(query: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Place name -> coordinates."""
    query = (query or "").strip()
    if not query:
        return {"status": "error", "detail": "Empty query"}
    try:
        res = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": query, "format": "json", "limit": 1},
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return {"status": "error", "detail": f"Nominatim unreachable: {exc}"}

    if res.status_code != 200:
        return {"status": "error", "detail": f"Nominatim HTTP {res.status_code}"}
    try:
        data = res.json()
    except ValueError:
        return {"status": "error", "detail": "Nominatim returned non-JSON data"}
    if not isinstance(data, list):
        return {"status": "error", "detail": "Nominatim returned an unexpected payload shape"}
    if not data or not isinstance(data[0], dict):
        return {"status": "empty", "detail": f"No place matched '{query}'"}
    item = data[0]
    return {
        "status": "ok",
        "detail": item.get("display_name", query),
        "lat": _f(item.get("lat")),
        "lon": _f(item.get("lon")),
        "display_name": item.get("display_name"),
        "boundingbox": [_f(v) for v in item.get("boundingbox", [])],
    }


def reverse_geocode(lat: float, lon: float, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Coordinates -> human-readable place name ("where am I?")."""
    try:
        res = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "json", "zoom": 18, "addressdetails": 1},
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return {"status": "error", "detail": f"Nominatim unreachable: {exc}"}

    if res.status_code != 200:
        return {"status": "error", "detail": f"Nominatim HTTP {res.status_code}"}
    try:
        data = res.json()
    except ValueError:
        return {"status": "error", "detail": "Nominatim returned non-JSON data"}
    if not isinstance(data, dict):
        return {"status": "error", "detail": "Nominatim returned an unexpected payload shape"}
    if not data or data.get("error"):
        return {"status": "empty", "detail": data.get("error", "No address for these coordinates")}
    return {
        "status": "ok",
        "detail": data.get("display_name", ""),
        "lat": lat,
        "lon": lon,
        "display_name": data.get("display_name"),
        "address": data.get("address", {}),
    }


# --------------------------------------------------------------------------- #
# WiGLE (Wi-Fi / Bluetooth / cell)
# --------------------------------------------------------------------------- #
def _wigle(endpoint: str, lat: float, lon: float, radius_km: float, creds: Credentials,
           timeout: int = DEFAULT_TIMEOUT) -> dict:
    if not creds.wigle_ready():
        return {"status": "skipped", "detail": "WIGLE_API_NAME / WIGLE_API_TOKEN not configured"}
    lat_min, lat_max, lon_min, lon_max = bounding_box(lat, lon, radius_km)
    try:
        res = requests.get(
            f"https://api.wigle.net/api/v2/{endpoint}",
            params={
                "latrange1": round(lat_min, 6),
                "latrange2": round(lat_max, 6),
                "longrange1": round(lon_min, 6),
                "longrange2": round(lon_max, 6),
            },
            auth=(creds.get("WIGLE_API_NAME"), creds.get("WIGLE_API_TOKEN")),
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return {"status": "error", "detail": f"WiGLE unreachable: {exc}"}

    if res.status_code == 401:
        return {"status": "error", "detail": "WiGLE rejected the credentials (HTTP 401)"}
    if res.status_code == 429:
        return {"status": "error", "detail": "WiGLE rate limit / daily quota reached (HTTP 429)"}
    if res.status_code != 200:
        return {"status": "error", "detail": f"WiGLE HTTP {res.status_code}: {res.text[:120]}"}
    try:
        payload = res.json()
    except ValueError:
        return {"status": "error", "detail": "WiGLE returned non-JSON data"}
    if payload.get("success") is False:
        return {"status": "error", "detail": f"WiGLE: {payload.get('message', 'query failed')}"}
    return {"status": "ok", "detail": "", "results": payload.get("results", []) or []}


def wigle_wifi(lat, lon, radius_km=1.0, creds=None, timeout=DEFAULT_TIMEOUT) -> dict:
    """Wi-Fi access points around a point (WiGLE ``network/search``)."""
    creds = creds or Credentials()
    raw = _wigle("network/search", lat, lon, radius_km, creds, timeout)
    if raw["status"] != "ok":
        return envelope("wigle_wifi", raw["status"], raw["detail"])

    devices = []
    for net in raw["results"]:
        nlat, nlon = _f(net.get("trilat")), _f(net.get("trilong"))
        if nlat is None or nlon is None:
            continue
        ssid = net.get("ssid") or "(hidden SSID)"
        devices.append(
            {
                "lat": nlat,
                "lon": nlon,
                "distance_km": round(haversine_km(lat, lon, nlat, nlon), 4),
                "ssid": ssid,
                "bssid": net.get("netid"),
                "vendor": net.get("vendor"),
                "signal": _f(net.get("level")),
                "channel": net.get("channel"),
                "encryption": net.get("encryption"),
                "qos": net.get("qos"),
                "timestamp": net.get("lastupdt"),
                "type": classify_device(ssid, "router"),
                "source": "wigle",
            }
        )
    devices.sort(key=lambda d: d["distance_km"])
    detail = f"{len(devices)} Wi-Fi networks from {len(raw['results'])} WiGLE rows"
    return envelope("wigle_wifi", "ok" if devices else "empty", detail, devices)


def wigle_bluetooth(lat, lon, radius_km=1.0, creds=None, timeout=DEFAULT_TIMEOUT) -> dict:
    """Bluetooth devices around a point (WiGLE ``bluetooth/search``)."""
    creds = creds or Credentials()
    raw = _wigle("bluetooth/search", lat, lon, radius_km, creds, timeout)
    if raw["status"] != "ok":
        return envelope("wigle_bluetooth", raw["status"], raw["detail"])

    devices = []
    for dev in raw["results"]:
        dlat, dlon = _f(dev.get("trilat")), _f(dev.get("trilong"))
        if dlat is None or dlon is None:
            continue
        name = dev.get("name") or dev.get("netid") or "(unnamed BLE)"
        devices.append(
            {
                "lat": dlat,
                "lon": dlon,
                "distance_km": round(haversine_km(lat, lon, dlat, dlon), 4),
                "ssid": name,
                "bssid": dev.get("netid"),
                "vendor": dev.get("type") or classify_device(name, "bluetooth"),
                "signal": _f(dev.get("level")),
                "timestamp": dev.get("lastupdt"),
                "type": classify_device(name, "bluetooth"),
                "source": "wigle",
            }
        )
    devices.sort(key=lambda d: d["distance_km"])
    detail = f"{len(devices)} Bluetooth devices from {len(raw['results'])} WiGLE rows"
    return envelope("wigle_bluetooth", "ok" if devices else "empty", detail, devices)


def wigle_cell(lat, lon, radius_km=1.5, creds=None, timeout=DEFAULT_TIMEOUT) -> dict:
    """Cell towers around a point (WiGLE ``cell/search``)."""
    creds = creds or Credentials()
    raw = _wigle("cell/search", lat, lon, radius_km, creds, timeout)
    if raw["status"] != "ok":
        return envelope("wigle_cell", raw["status"], raw["detail"])

    devices = []
    for cell in raw["results"]:
        clat, clon = _f(cell.get("trilat")), _f(cell.get("trilong"))
        if clat is None or clon is None:
            continue
        gentype = cell.get("gentype") or cell.get("radio") or "GSM"
        cid = str(cell.get("id") or cell.get("cellid") or "CellTower")
        place = cell.get("road") or cell.get("city") or "Cellular Mast"
        devices.append(
            {
                "lat": clat,
                "lon": clon,
                "distance_km": round(haversine_km(lat, lon, clat, clon), 4),
                "ssid": f"[{gentype}] {cid}",
                "cell_id": cid,
                "vendor": f"WiGLE Cell ({gentype}) · {place}",
                "radio": gentype,
                "signal": _f(cell.get("qos"), -68),
                "timestamp": cell.get("lastupdt"),
                "type": "cell_tower",
                "source": "wigle",
            }
        )
    devices.sort(key=lambda d: d["distance_km"])
    detail = f"{len(devices)} cell towers from {len(raw['results'])} WiGLE rows"
    return envelope("wigle_cell", "ok" if devices else "empty", detail, devices)


# --------------------------------------------------------------------------- #
# OpenCellID
# --------------------------------------------------------------------------- #
def opencellid_towers(lat, lon, radius_km=1.5, creds=None, timeout=DEFAULT_TIMEOUT) -> dict:
    """Cell towers from OpenCellID: primary ``getInArea``, fallback public ajax feed."""
    creds = creds or Credentials()
    lat_min, lat_max, lon_min, lon_max = bounding_box(lat, lon, radius_km)
    devices, notes = [], []

    key = creds.get("OPENCELLID_API_KEY")
    if key:
        try:
            res = requests.get(
                "http://opencellid.org/cell/getInArea",
                params={
                    "key": key,
                    "BBOX": f"{lat_min:.6f},{lon_min:.6f},{lat_max:.6f},{lon_max:.6f}",
                    "format": "json",
                },
                headers={"User-Agent": USER_AGENT},
                timeout=timeout,
            )
            if res.status_code == 200:
                try:
                    payload = res.json()
                except ValueError:
                    payload = None
                rows = payload if isinstance(payload, list) else (payload or {}).get("cells", [])
                for cell in rows or []:
                    clat, clon = _f(cell.get("lat")), _f(cell.get("lon"))
                    if clat is None or clon is None:
                        continue
                    radio = str(cell.get("radio") or "GSM").upper()
                    cid = str(cell.get("cellid") or cell.get("cid") or "")
                    devices.append(
                        {
                            "lat": clat,
                            "lon": clon,
                            "distance_km": round(haversine_km(lat, lon, clat, clon), 4),
                            "ssid": f"OpenCellID [{radio}] CID:{cid or 'n/a'}",
                            "cell_id": cid,
                            "radio": radio,
                            "vendor": (
                                f"OpenCellID · MCC:{cell.get('mcc', '')} "
                                f"MNC:{cell.get('mnc', '')} LAC:{cell.get('lac', '')}"
                            ),
                            "signal": _f(cell.get("signal"), -65),
                            "timestamp": cell.get("updated"),
                            "type": "cell_tower",
                            "source": "opencellid",
                        }
                    )
                notes.append(f"getInArea: {len(devices)} cells")
            else:
                notes.append(f"getInArea HTTP {res.status_code}")
        except requests.RequestException as exc:
            notes.append(f"getInArea unreachable: {exc}")
    else:
        notes.append("getInArea skipped: OPENCELLID_API_KEY not configured")

    # Public GeoJSON feed — no key required, so it is always attempted as a fallback.
    if not devices:
        try:
            res = requests.get(
                "https://www.opencellid.org/ajax/getCells.php",
                params={
                    "bbox": (
                        f"{lon_min:.6f},{lat_min:.6f},{lon_max:.6f},{lat_max:.6f}"
                    )
                },
                headers={"User-Agent": USER_AGENT},
                timeout=timeout,
            )
            if res.status_code == 200:
                for feat in res.json().get("features", []) or []:
                    props = feat.get("properties", {}) or {}
                    coords = (feat.get("geometry", {}) or {}).get("coordinates") or []
                    if len(coords) < 2:
                        continue
                    clon, clat = _f(coords[0]), _f(coords[1])
                    if clat is None or clon is None:
                        continue
                    radio = str(props.get("radio") or "GSM").upper()
                    cid = str(props.get("cellid") or props.get("unit") or "")
                    devices.append(
                        {
                            "lat": clat,
                            "lon": clon,
                            "distance_km": round(haversine_km(lat, lon, clat, clon), 4),
                            "ssid": f"OpenCellID [{radio}] CID:{cid or 'n/a'}",
                            "cell_id": cid,
                            "radio": radio,
                            "vendor": (
                                f"OpenCellID · MCC:{props.get('mcc', '')} "
                                f"MNC:{props.get('net', '')} LAC:{props.get('area', '')}"
                            ),
                            "signal": -65,
                            "timestamp": props.get("updated"),
                            "type": "cell_tower",
                            "source": "opencellid",
                        }
                    )
                notes.append(f"ajax getCells: {len(devices)} cells")
            else:
                notes.append(f"ajax getCells HTTP {res.status_code}")
        except (requests.RequestException, ValueError) as exc:
            notes.append(f"ajax getCells failed: {exc}")

    devices.sort(key=lambda d: d["distance_km"])
    detail = " · ".join(notes)
    if devices:
        return envelope("opencellid", "ok", detail, devices)
    # Nothing came back: separate "the service answered with zero cells" from a
    # real failure, so an empty area is never reported as a broken integration.
    failed = any(marker in detail for marker in ("HTTP", "unreachable", "failed"))
    return envelope("opencellid", "error" if failed else "empty", detail)


# --------------------------------------------------------------------------- #
# Shodan / Censys (IoT, SCADA, exposed cameras)
# --------------------------------------------------------------------------- #
def shodan_geo(lat, lon, radius_km=5.0, creds=None, limit=50, timeout=DEFAULT_TIMEOUT) -> dict:
    """Internet-facing devices in a geo circle via the Shodan host search API."""
    creds = creds or Credentials()
    key = creds.get("SHODAN_API_KEY")
    if not key:
        return envelope("shodan", "skipped", "SHODAN_API_KEY not configured")

    try:
        res = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": key, "query": f"geo:{lat},{lon},{radius_km}", "limit": limit},
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return envelope("shodan", "error", f"Shodan unreachable: {exc}")

    if res.status_code != 200:
        try:
            msg = res.json().get("error", res.text[:120])
        except ValueError:
            msg = res.text[:120]
        return envelope("shodan", "error", f"Shodan HTTP {res.status_code}: {msg}")

    devices = []
    for match in res.json().get("matches", []) or []:
        loc = match.get("location", {}) or {}
        dlat, dlon = _f(loc.get("latitude")), _f(loc.get("longitude"))
        if dlat is None or dlon is None:
            continue  # never plot a device without genuine coordinates
        ip = match.get("ip_str")
        port = match.get("port", 80)
        product = match.get("product") or (match.get("_shodan") or {}).get("module") or "IoT Device"
        banner = (match.get("data") or "")[:200]
        dev_type = classify_device(f"{product} {banner}", "iot_device")
        if "cam" in str(product).lower() or "rtsp" in banner.lower() or port in (554, 8000, 37777):
            dev_type = "camera"
        devices.append(
            {
                "lat": dlat,
                "lon": dlon,
                "distance_km": round(haversine_km(lat, lon, dlat, dlon), 4),
                "ssid": f"[{str(product).upper()}:{port}] {ip}",
                "ip": ip,
                "port": port,
                "vendor": f"Shodan · {match.get('org') or match.get('isp') or 'ISP Host'} (port {port})",
                "product": product,
                "org": match.get("org") or match.get("isp"),
                "info": banner[:120].strip(),
                "timestamp": match.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                "type": dev_type,
                "source": "shodan",
            }
        )
    devices.sort(key=lambda d: d["distance_km"])
    total = res.json().get("total")
    detail = f"{len(devices)} geolocated hosts (Shodan total matches: {total})"
    return envelope("shodan", "ok" if devices else "empty", detail, devices)


def censys_geo(lat, lon, radius_km=5.0, creds=None, per_page=50, timeout=DEFAULT_TIMEOUT) -> dict:
    """Internet-facing hosts in a bounding box via the Censys Search API v2."""
    creds = creds or Credentials()
    api_id, api_secret = creds.get("CENSYS_API_ID"), creds.get("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return envelope("censys", "skipped", "CENSYS_API_ID / CENSYS_API_SECRET not configured")

    lat_min, lat_max, lon_min, lon_max = bounding_box(lat, lon, radius_km)
    query = (
        f"location.coordinates.latitude:[{lat_min:.4f} TO {lat_max:.4f}] AND "
        f"location.coordinates.longitude:[{lon_min:.4f} TO {lon_max:.4f}]"
    )
    try:
        res = requests.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": query, "per_page": per_page},
            auth=(api_id, api_secret),
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return envelope("censys", "error", f"Censys unreachable: {exc}")

    if res.status_code != 200:
        try:
            msg = res.json().get("error", res.text[:120])
        except ValueError:
            msg = res.text[:120]
        return envelope("censys", "error", f"Censys HTTP {res.status_code}: {msg}")

    devices = []
    for host in (res.json().get("result", {}) or {}).get("hits", []) or []:
        coords = ((host.get("location") or {}).get("coordinates") or {})
        dlat, dlon = _f(coords.get("latitude")), _f(coords.get("longitude"))
        if dlat is None or dlon is None:
            continue
        services = host.get("services") or []
        svc = services[0] if services else {}
        port = svc.get("port", 80)
        svc_name = svc.get("service_name", "HTTP")
        as_name = (host.get("autonomous_system") or {}).get("name") or "Telecom AS"
        dev_type = "camera" if ("rtsp" in str(svc_name).lower() or port in (554, 8000, 37777)) else "iot_device"
        devices.append(
            {
                "lat": dlat,
                "lon": dlon,
                "distance_km": round(haversine_km(lat, lon, dlat, dlon), 4),
                "ssid": f"[CENSYS:{str(svc_name).upper()}:{port}] {host.get('ip')}",
                "ip": host.get("ip"),
                "port": port,
                "vendor": f"Censys · {as_name} ({svc_name})",
                "product": svc_name,
                "org": as_name,
                "info": f"Protocol {svc_name} on port {port} · AS {as_name}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": dev_type,
                "source": "censys",
            }
        )
    devices.sort(key=lambda d: d["distance_km"])
    detail = f"{len(devices)} geolocated hosts"
    return envelope("censys", "ok" if devices else "empty", detail, devices)


def scan_iot(lat, lon, radius_km=5.0, creds=None, use_shodan=True, use_censys=True,
             category="all", limit=50, timeout=DEFAULT_TIMEOUT) -> dict:
    """Shodan + Censys combined, in one envelope."""
    creds = creds or Credentials()
    sources = []
    if use_shodan:
        sources.append(shodan_geo(lat, lon, radius_km, creds, limit=limit, timeout=timeout))
    if use_censys:
        sources.append(censys_geo(lat, lon, radius_km, creds, per_page=limit, timeout=timeout))

    devices = [d for s in sources for d in s["devices"]]
    if category and category != "all":
        needle = category.lower()
        devices = [
            d for d in devices
            if needle in str(d.get("type", "")).lower() or needle in str(d.get("product", "")).lower()
        ]
    devices.sort(key=lambda d: d["distance_km"])

    if not sources:
        return envelope("iot", "skipped", "both Shodan and Censys disabled")

    statuses = {s["source"]: f"{s['status']} — {s['detail']}" for s in sources}
    results = [s["status"] for s in sources]
    if "ok" in results:
        status = "ok"
    elif all(s == "skipped" for s in results):
        status = "skipped"
    elif "error" in results:
        status = "error"
    else:
        status = "empty"

    return {
        "source": "iot",
        "status": status,
        "detail": "; ".join(f"{k}: {v}" for k, v in statuses.items()),
        "count": len(devices),
        "devices": devices,
        "sources": sources,
    }


# --------------------------------------------------------------------------- #
# Offline sources: Flock / ALPR datasets and imported telemetry
# --------------------------------------------------------------------------- #
def flock_near(lat, lon, radius_km=25.0, datasets=None, limit=250) -> dict:
    """ALPR / Flock Safety cameras within ``radius_km`` of a point.

    Uses the datasets already present in ``uploads/flock`` — fully offline.
    """
    try:
        catalog = flock_manager.get_catalog()
    except Exception as exc:  # pragma: no cover - defensive
        return envelope("flock", "error", f"Could not read the Flock catalog: {exc}")

    wanted = None
    if datasets:
        wanted = {d.lower() for d in datasets}

    found, scanned, missing = [], [], []
    for entry in catalog:
        if not entry.get("is_downloaded"):
            missing.append(entry["filename"])
            continue
        if wanted and entry["filename"].lower() not in wanted and entry["id"].lower() not in wanted:
            continue
        try:
            result = flock_manager.get_all_dataset_cameras(entry["filename"], limit=20000)
        except Exception as exc:
            missing.append(f"{entry['filename']} ({exc})")
            continue
        if result.get("status") != "success":
            missing.append(entry["filename"])
            continue
        scanned.append(f"{entry['filename']}:{result.get('count', 0)}")
        for cam in result.get("cameras", []):
            cam_lat, cam_lon = _f(cam.get("lat")), _f(cam.get("lon"))
            if cam_lat is None or cam_lon is None:
                continue
            dist = haversine_km(lat, lon, cam_lat, cam_lon)
            if dist <= radius_km:
                cam = dict(cam)
                cam.update(
                    {
                        "distance_km": round(dist, 4),
                        "ssid": cam.get("name"),
                        "type": "alpr_camera",
                        "source": f"flock:{entry['filename']}",
                    }
                )
                found.append(cam)

    found.sort(key=lambda d: d["distance_km"])
    detail = f"scanned {', '.join(scanned) if scanned else 'no local datasets'}"
    if missing:
        detail += f" | not available locally: {', '.join(missing)}"
    return envelope("flock", "ok" if found else "empty", detail, found[:limit])


# US state names -> postal abbreviations, so "Florida" and "FL" both work.
STATE_ABBREV = {
    "alabama": "AL", "alaska": "AK", "arizona": "AZ", "arkansas": "AR", "california": "CA",
    "colorado": "CO", "connecticut": "CT", "delaware": "DE", "florida": "FL", "georgia": "GA",
    "hawaii": "HI", "idaho": "ID", "illinois": "IL", "indiana": "IN", "iowa": "IA",
    "kansas": "KS", "kentucky": "KY", "louisiana": "LA", "maine": "ME", "maryland": "MD",
    "massachusetts": "MA", "michigan": "MI", "minnesota": "MN", "mississippi": "MS",
    "missouri": "MO", "montana": "MT", "nebraska": "NE", "nevada": "NV",
    "new hampshire": "NH", "new jersey": "NJ", "new mexico": "NM", "new york": "NY",
    "north carolina": "NC", "north dakota": "ND", "ohio": "OH", "oklahoma": "OK",
    "oregon": "OR", "pennsylvania": "PA", "rhode island": "RI", "south carolina": "SC",
    "south dakota": "SD", "tennessee": "TN", "texas": "TX", "utah": "UT", "vermont": "VT",
    "virginia": "VA", "washington": "WA", "west virginia": "WV", "wisconsin": "WI",
    "wyoming": "WY", "district of columbia": "DC",
}
_STATE_BY_ABBREV = {v: v for v in STATE_ABBREV.values()}


def parse_bbox(text):
    """Parse ``"south,west,north,east"`` (OSM order) into ``(lat_min, lon_min, lat_max, lon_max)``."""
    if not text:
        return None
    parts = [p.strip() for p in str(text).replace(";", ",").split(",") if p.strip()]
    if len(parts) != 4:
        raise ValueError("bbox needs four numbers: south,west,north,east (e.g. 26.23,-80.90,27.00,-80.00)")
    try:
        south, west, north, east = (float(p) for p in parts)
    except ValueError:
        raise ValueError("bbox values must be numbers: south,west,north,east")
    if not (-90 <= south <= 90 and -90 <= north <= 90 and -180 <= west <= 180 and -180 <= east <= 180):
        raise ValueError("bbox out of range")
    if south > north or west > east:
        raise ValueError("bbox must be south<=north and west<=east")
    return south, west, north, east


def normalise_region(text):
    """``Florida`` / ``fl`` / ``FL,`` -> ``FL``; anything unrecognised -> ``""``."""
    token = str(text or "").strip().lower().rstrip(".,;")
    if not token:
        return ""
    if token in STATE_ABBREV:
        return STATE_ABBREV[token]
    upper = token.upper()
    if upper in _STATE_BY_ABBREV:
        return upper
    return ""


# Raw fields worth keeping next to the normalised camera record.
_FLOCK_RAW_FIELDS = ("region", "city", "road", "postalcode", "housenumber", "ssid", "netid",
                     "device", "mfgrid", "capabilities", "firsttime", "lasttime", "lastupdt",
                     "country", "type", "operator", "brand", "notes", "maps_url")


def split_place_state(text):
    """Split ``"Palm Beach Florida"`` into ``("palm beach", "FL")``.

    Handles two-word state names and postal abbreviations; returns ``""`` as the
    region when the text carries no state.
    """
    tokens = str(text or "").strip().split()
    if not tokens:
        return "", ""
    if len(tokens) >= 2:
        two = " ".join(tokens[-2:]).lower().rstrip(".,;")
        if two in STATE_ABBREV:
            return " ".join(tokens[:-2]).strip(), STATE_ABBREV[two]
    last = tokens[-1].lower().rstrip(".,;")
    if last in STATE_ABBREV:
        return " ".join(tokens[:-1]).strip(), STATE_ABBREV[last]
    if last.upper() in _STATE_BY_ABBREV:
        return " ".join(tokens[:-1]).strip(), last.upper()
    return str(text).strip(), ""


def flock_search(query=None, region=None, bbox=None, cities=None, zip_prefix=None, lat=None,
                 lon=None, radius_km=None, datasets=None, limit=5000, strict_region=False):
    """Search the local ALPR/Flock datasets by text, state, bounding box and/or radius.

    Unlike :func:`flock_near` this is a *query*, not a proximity scan: it is what
    you want for "find every road camera in Palm Beach County, Florida".

    ``region`` accepts ``FL`` or ``Florida``.  ``bbox`` is ``south,west,north,east``.
    ``zip_prefix`` takes a comma-separated list of postal prefixes ("334,329") —
    the reliable way to pin down a US county, since a bounding box also catches
    neighbouring counties and many rows have no city recorded.

    Several datasets (maximum_dots, DeFlock) carry no state column at all. By
    default those rows are *kept* when filtering by region — dropping them would
    silently hide real matches — but they are counted, reported in ``detail`` and
    returned as ``region_unstated``; ``strict_region=True`` excludes them.
    """
    try:
        catalog = flock_manager.get_catalog()
    except Exception as exc:  # pragma: no cover - defensive
        return envelope("flock", "error", f"Could not read the Flock catalog: {exc}")

    wanted = {d.lower() for d in datasets} if datasets else None
    region_norm = normalise_region(region) if region else ""
    box = parse_bbox(bbox) if bbox else None
    city_needles = [c.strip().lower() for c in (cities or []) if c.strip()]
    zip_prefixes = [str(z).strip() for z in str(zip_prefix or "").replace(";", ",").split(",")
                    if z.strip()]
    text = (query or "").strip().lower()

    found, scanned, missing = [], [], []
    stated = unstated = 0
    for entry in catalog:
        if not entry.get("is_downloaded"):
            missing.append(entry["filename"])
            continue
        if wanted and entry["filename"].lower() not in wanted and entry["id"].lower() not in wanted:
            continue
        try:
            raw_records = flock_manager.load_flock_file_raw_records(
                os.path.join(flock_manager.FLOCK_DIR, entry["filename"])
            )
        except Exception as exc:
            missing.append(f"{entry['filename']} ({exc})")
            continue
        scanned.append(f"{entry['filename']}:{len(raw_records)}")

        for idx, row in enumerate(raw_records):
            cam = flock_manager.normalize_camera_record(row, idx, entry["filename"])
            if not cam:
                continue
            cam_lat, cam_lon = _f(cam.get("lat")), _f(cam.get("lon"))
            if cam_lat is None or cam_lon is None:
                continue

            raw = row if isinstance(row, dict) else {}
            city = str(raw.get("city") or "").strip()
            road = str(raw.get("road") or "").strip()
            row_region = str(raw.get("region") or "").strip().upper()

            if region_norm:
                if row_region and row_region != region_norm:
                    continue
                if not row_region and strict_region:
                    continue
            if box and not (box[0] <= cam_lat <= box[2] and box[1] <= cam_lon <= box[3]):
                continue
            if lat is not None and lon is not None and radius_km:
                if haversine_km(lat, lon, cam_lat, cam_lon) > radius_km:
                    continue
            if city_needles and not any(n in city.lower() for n in city_needles):
                continue
            if zip_prefixes:
                postal = str(raw.get("postalcode") or "").strip()
                if not any(postal.startswith(prefix) for prefix in zip_prefixes):
                    continue
            if text:
                blob = " ".join(
                    str(raw.get(k) or cam.get(k) or "")
                    for k in ("name", "city", "road", "ssid", "netid", "operator", "brand",
                              "notes", "description", "postalcode", "device", "info/comments")
                ).lower()
                if text not in blob:
                    continue

            record = {
                "lat": cam_lat,
                "lon": cam_lon,
                "distance_km": (round(haversine_km(lat, lon, cam_lat, cam_lon), 4)
                                if lat is not None and lon is not None else None),
                "ssid": cam.get("name"),
                "name": cam.get("name"),
                "bssid": str(raw.get("netid") or "") or None,
                "brand": cam.get("brand"),
                "operator": cam.get("operator"),
                "mount_type": cam.get("mount_type"),
                "direction": cam.get("direction"),
                "zone": cam.get("zone"),
                "maps_url": cam.get("maps_url"),
                "city": city,
                "road": road,
                "region": row_region,
                "type": "alpr_camera",
                "source": f"flock:{entry['filename']}",
            }
            for field in _FLOCK_RAW_FIELDS:
                value = raw.get(field)
                if value not in (None, "") and record.get(field) in (None, ""):
                    record[field] = str(value)
            found.append(record)
            if region_norm:
                if row_region:
                    stated += 1
                else:
                    unstated += 1

    found.sort(key=lambda d: (d.get("region") or "", d.get("city") or "", d.get("road") or "",
                              d.get("lat") or 0))
    found = found[:limit]

    filters = []
    if text:
        filters.append(f"text='{text}'")
    if region_norm:
        filters.append(f"region={region_norm}")
        if unstated:
            filters.append(
                f"{stated} rows state it + {unstated} kept with no state recorded"
                f" (strict_region excludes those)"
            )
        else:
            filters.append(f"{stated} rows state it")
    if box:
        filters.append(f"bbox={box[0]},{box[1]},{box[2]},{box[3]}")
    if city_needles:
        filters.append("cities=" + "|".join(city_needles))
    if zip_prefixes:
        filters.append("zip=" + "|".join(zip_prefixes))
    if lat is not None and radius_km:
        filters.append(f"radius={radius_km}km@{lat},{lon}")
    detail = (f"{len(found)} matches ({', '.join(filters) or 'no filter'}) · "
              f"scanned {', '.join(scanned) if scanned else 'no local datasets'}")
    if missing:
        detail += f" | not available locally: {', '.join(missing)}"
    result = envelope("flock", "ok" if found else "empty", detail, found)
    result["region_stated"] = stated
    result["region_unstated"] = unstated
    return result


EXPORT_COLUMNS = ["lat", "lon", "region", "city", "road", "name", "brand", "operator",
                  "ssid", "bssid", "netid", "device", "postalcode", "mount_type", "direction",
                  "zone", "lasttime", "maps_url", "distance_km", "source"]


def cameras_to_geojson(cameras) -> dict:
    """Result set as a GeoJSON FeatureCollection (lon/lat live in the geometry)."""
    return {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [c["lon"], c["lat"]]},
                "properties": {k: v for k, v in c.items() if k not in ("lat", "lon")},
            }
            for c in cameras or []
        ],
    }


def cameras_to_csv(cameras) -> str:
    """Result set as CSV text with a stable column order."""
    import csv as _csv
    import io as _io

    buffer = _io.StringIO()
    writer = _csv.DictWriter(buffer, fieldnames=EXPORT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for cam in cameras or []:
        writer.writerow({k: cam.get(k, "") for k in EXPORT_COLUMNS})
    return buffer.getvalue()


def export_cameras(cameras, path):
    """Write search results to CSV or GeoJSON (extension decides the format)."""
    if not cameras:
        return {"status": "error", "detail": "nothing to export", "path": None}
    path = os.path.expanduser(str(path))
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    if os.path.splitext(path)[1].lower() == ".geojson":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cameras_to_geojson(cameras), fh, indent=1, default=str)
    else:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(cameras_to_csv(cameras))

    return {"status": "ok", "detail": f"wrote {len(cameras)} cameras", "path": path,
            "bytes": os.path.getsize(path)}


def flock_download(dataset_id):
    """Download one catalog dataset (needs egress to the dataset host)."""
    try:
        return flock_manager.download_dataset(dataset_id)
    except Exception as exc:  # pragma: no cover - network dependent
        return {"status": "error", "message": f"{type(exc).__name__}: {exc}"}


def flock_datasets() -> dict:
    """Catalog of ALPR datasets with local availability and record counts."""
    try:
        return {"status": "ok", "detail": "", "datasets": flock_manager.get_catalog()}
    except Exception as exc:
        return {"status": "error", "detail": str(exc), "datasets": []}


def import_telemetry(path: str, mappings=None) -> dict:
    """Preview (``mappings=None``) or fully process a telemetry file.

    ``telemetry_importer`` needs pandas, so it is imported lazily — a CLI user
    who only queries coordinates never pays for it.
    """
    if not os.path.exists(path):
        return {"status": "error", "detail": f"File not found: {path}"}
    try:
        import telemetry_importer
    except ImportError as exc:
        return {"status": "error", "detail": f"telemetry import unavailable: {exc}"}
    if mappings is None:
        return telemetry_importer.preview_file(path)
    return telemetry_importer.process_file(path, mappings)


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def scan(lat, lon, radius_km=1.0, modes=("wifi",), creds=None, iot_radius_km=None,
         limit=100, timeout=DEFAULT_TIMEOUT, parallel=True, use_shodan=True,
         use_censys=True) -> dict:
    """Run several coordinate-driven sources and merge the results.

    Returns::

        {"lat": .., "lon": .., "radius_km": ..,
         "sources": [envelope, ...],
         "devices": [...merged, sorted by distance...],
         "count": int}
    """
    creds = creds or Credentials()
    modes = tuple(dict.fromkeys(m.lower() for m in modes))  # de-dupe, keep order
    iot_radius = iot_radius_km if iot_radius_km is not None else max(radius_km, 5.0)

    jobs = {}
    for mode in modes:
        if mode == "wifi":
            jobs[mode] = lambda: wigle_wifi(lat, lon, radius_km, creds, timeout)
        elif mode in ("bluetooth", "bt", "ble"):
            jobs[mode] = lambda: wigle_bluetooth(lat, lon, radius_km, creds, timeout)
        elif mode == "cell":
            jobs[mode] = lambda: _cell_sources(lat, lon, radius_km, creds, timeout)
        elif mode == "iot":
            jobs[mode] = lambda: scan_iot(lat, lon, iot_radius, creds, use_shodan=use_shodan,
                                          use_censys=use_censys, limit=limit)
        elif mode == "flock":
            jobs[mode] = lambda: flock_near(lat, lon, radius_km)
        elif mode == "sdr":
            jobs[mode] = lambda: _sdr_probe()

    results = {}
    if parallel and len(jobs) > 1:
        with ThreadPoolExecutor(max_workers=min(len(jobs), 6)) as pool:
            futures = {name: pool.submit(fn) for name, fn in jobs.items()}
            for name, future in futures.items():
                try:
                    results[name] = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    results[name] = envelope(name, "error", f"{type(exc).__name__}: {exc}")
    else:
        for name, fn in jobs.items():
            try:
                results[name] = fn()
            except Exception as exc:  # pragma: no cover - defensive
                results[name] = envelope(name, "error", f"{type(exc).__name__}: {exc}")

    sources = []
    for mode in modes:
        res = results.get(mode)
        if res is None:
            sources.append(envelope(mode, "skipped", "unknown mode"))
            continue
        if isinstance(res, list):  # cell mode returns several envelopes
            sources.extend(res)
        else:
            sources.append(res)

    merged, seen = [], set()
    for src in sources:
        for dev in src.get("devices", []):
            key = (
                round(dev.get("lat", 0), 6),
                round(dev.get("lon", 0), 6),
                str(dev.get("bssid") or dev.get("ip") or dev.get("id") or dev.get("ssid")),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(dev)
    merged.sort(key=lambda d: d.get("distance_km", 0))

    return {
        "lat": lat,
        "lon": lon,
        "radius_km": radius_km,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": sources,
        "devices": merged[:limit],
        "count": len(merged),
    }


def _cell_sources(lat, lon, radius_km, creds, timeout):
    return [
        wigle_cell(lat, lon, radius_km, creds, timeout),
        opencellid_towers(lat, lon, radius_km, creds, timeout),
    ]


# --------------------------------------------------------------------------- #
# Connectivity self-test
# --------------------------------------------------------------------------- #
def self_test(creds=None, timeout=8) -> dict:
    """Report which upstream services are reachable and which keys are set.

    Deliberately tiny requests: Nominatim (no key), Shodan info (key),
    WiGLE token check, Censys quota, OpenCellID ajax feed.
    """
    creds = creds or Credentials()
    checks = []

    def add(name, url, ok_fn, needs_key=None, **kwargs):
        entry = {"name": name, "url": url, "key_configured": None}
        if needs_key is not None:
            entry["key_configured"] = creds.has(needs_key) if isinstance(needs_key, str) else all(
                creds.has(k) for k in needs_key
            )
            if not entry["key_configured"]:
                entry.update({"reachable": None, "detail": "skipped — key not configured"})
                checks.append(entry)
                return
        try:
            res = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT}, **kwargs)
            entry["reachable"] = True
            entry["http_status"] = res.status_code
            entry["detail"] = ok_fn(res)
        except requests.RequestException as exc:
            entry["reachable"] = False
            entry["detail"] = f"{type(exc).__name__}: {str(exc)[:110]}"
        checks.append(entry)

    add("Nominatim (geocoding)", "https://nominatim.openstreetmap.org/status", lambda r: r.text[:80].strip() or "reachable")
    add("WiGLE", "https://api.wigle.net/api/v2/user/token", lambda r: ("token accepted" if r.status_code == 200 else f"HTTP {r.status_code}"), needs_key=["WIGLE_API_NAME", "WIGLE_API_TOKEN"])
    add("Shodan", "https://api.shodan.io/api-info", lambda r: ("key accepted" if r.status_code == 200 else f"HTTP {r.status_code}"), needs_key="SHODAN_API_KEY", params={"key": creds.get("SHODAN_API_KEY")})
    add("OpenCellID ajax feed", "https://www.opencellid.org/ajax/getCells.php", lambda r: f"HTTP {r.status_code}", params={"bbox": "-0.02,51.49,-0.01,51.50"})
    add("Censys", "https://search.censys.io/api/v2/account", lambda r: ("account reachable" if r.status_code == 200 else f"HTTP {r.status_code}"), needs_key=["CENSYS_API_ID", "CENSYS_API_SECRET"], auth=(creds.get("CENSYS_API_ID"), creds.get("CENSYS_API_SECRET")))

    sdr = detect_sdr()
    checks.append(
        {
            "name": "USB SDR dongle",
            "url": "/sys/bus/usb/devices",
            "key_configured": None,
            "reachable": sdr["connected"],
            "detail": f"{sdr['device']} — {sdr['detail']}",
        }
    )

    local = flock_datasets()
    downloaded = [d for d in local["datasets"] if d.get("is_downloaded")]
    checks.append(
        {
            "name": "Local Flock/ALPR datasets",
            "url": flock_manager.FLOCK_DIR,
            "key_configured": None,
            "reachable": bool(downloaded),
            "detail": (
                f"{len(downloaded)} datasets, "
                f"{sum(d.get('camera_count') or 0 for d in downloaded)} camera records"
            ),
        }
    )

    return {
        "credentials": creds.report(),
        "checks": checks,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def to_json(obj, indent=2) -> str:
    """Stable JSON dump for ``--json`` output and chat pasting."""
    return json.dumps(obj, indent=indent, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------- #
# Local analyst: turn a free-form chat line into a coordinate-driven answer
# --------------------------------------------------------------------------- #
_COORD_RE = re.compile(
    r"(-?\d{1,3}(?:[.,]\d+)?)\s*(?:°\s*)?([NS]?)\s*[,;\s]\s*"
    r"(-?\d{1,3}(?:[.,]\d+)?)\s*(?:°\s*)?([EW]?)",
    re.IGNORECASE,
)
_RADIUS_RE = re.compile(r"(\d+(?:[.,]\d+)?)\s*(km|км|k|mi|miles?|m|м|nm)\b", re.IGNORECASE)

_INTENT_WORDS = {
    "wifi": ("wifi", "wi-fi", "access point", "router", "ssid", "вайфай", "роутер", "сеть", "сети"),
    "bluetooth": ("bluetooth", "ble", "airpod", "headphone", "блютуз", "гарнитур"),
    "cell": ("cell", "cellular", "tower", "bts", "lte", "gsm", "вышк", "сотов", "базов"),
    "iot": ("iot", "scada", "shodan", "censys", "ip camera", "камер", "iot-устройств"),
    "flock": ("alpr", "flock", "license plate", "plate reader", "номер", "alpr-камер"),
    "sdr": ("sdr", "rtl-sdr", "hackrf", "airspy", "spectrum", "радио", "эфир"),
}

_ALL_MODES = MODES


_DMS_RE = re.compile(
    r"(\d{1,3})\s*°\s*(\d{1,2}(?:[.,]\d+)?)?\s*"
    r"(?:['′]\s*(\d{1,2}(?:[.,]\d+)?)?\s*)?(?:[\"″]\s*)?([NSEW])?",
    re.IGNORECASE,
)


def _dms_to_decimal(degrees, minutes, seconds, hemisphere) -> float:
    value = float(degrees)
    if minutes:
        value += float(str(minutes).replace(",", ".")) / 60.0
    if seconds:
        value += float(str(seconds).replace(",", ".")) / 3600.0
    if (hemisphere or "").upper() in ("S", "W"):
        value = -value
    return value


def _parse_dms(text: str):
    """Parse ``47°12.4'N 27°47.7'E`` (and the ° ' " variants) into decimal degrees."""
    lat = lon = None
    for match in _DMS_RE.finditer(text or ""):
        if not match.group(0).strip():
            continue
        hemi = (match.group(4) or "").upper()
        value = _dms_to_decimal(match.group(1), match.group(2), match.group(3), hemi)
        if hemi in ("N", "S") or (hemi == "" and lat is None):
            if lat is None:
                lat = value
        elif hemi in ("E", "W") or (hemi == "" and lon is None):
            if lon is None:
                lon = value
    if lat is None or lon is None:
        return None
    if -90 <= lat <= 90 and -180 <= lon <= 180:
        return lat, lon
    return None


def extract_coordinates(text: str):
    """Pull a ``(lat, lon)`` pair out of free-form text, or return ``None``.

    Decimal degrees (``47.2066 27.7950``) and degrees/minutes
    (``47°12.4'N 27°47.7'E``) are both understood.  Text containing a degree
    sign is only ever parsed as DMS, so a half-understood DMS string never
    turns into a wrong decimal coordinate.
    """
    if "°" in (text or ""):
        return _parse_dms(text)
    for match in _COORD_RE.finditer(text or ""):
        lat = float(match.group(1).replace(",", "."))
        lon = float(match.group(3).replace(",", "."))
        if match.group(2).upper() == "S":
            lat = -abs(lat)
        if match.group(4).upper() == "W":
            lon = -abs(lon)
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return lat, lon
    return None


def extract_radius_km(text: str, default: float = 1.0) -> float:
    """Pull a radius such as ``2km`` / ``500 m`` / ``3 км`` out of free-form text."""
    match = _RADIUS_RE.search(text or "")
    if not match:
        return default
    value = float(match.group(1).replace(",", "."))
    unit = match.group(2).lower()
    if unit in ("m", "м"):
        return value / 1000.0
    if unit == "mi" or unit.startswith("mile"):
        return value * 1.609344
    if unit == "nm":
        return value * 1.852
    return value


def detect_intents(text: str) -> tuple:
    """Which sources does this message ask about? Empty tuple means 'everything'."""
    lowered = (text or "").lower()
    found = tuple(mode for mode, words in _INTENT_WORDS.items() if any(w in lowered for w in words))
    if any(w in lowered for w in ("all", "everything", "всё", "все источники", "around me", "вокруг")):
        return _ALL_MODES
    return found


def summarise_scan(result: dict, place: str = "", top: int = 6) -> str:
    """Plain-language summary of a :func:`scan` result — used by chat answers."""
    lines = []
    header = f"{result['lat']}, {result['lon']} · radius {result['radius_km']:.3g} km"
    if place:
        header += f" · {place}"
    lines.append(header)

    ok_sources, quiet_sources = [], []
    for src in result["sources"]:
        label = src.get("source", "?")
        if src.get("status") == "ok" and src.get("count"):
            ok_sources.append(f"{label}: {src['count']}")
        else:
            reason = src.get("detail") or src.get("status")
            quiet_sources.append(f"{label} ({src.get('status')}): {reason[:90]}")

    if ok_sources:
        lines.append("answered: " + ", ".join(ok_sources))
    else:
        lines.append("no source returned data for this point.")

    for dev in result["devices"][:top]:
        ident = dev.get("bssid") or dev.get("cell_id") or dev.get("ip") or dev.get("id") or ""
        name = dev.get("ssid") or dev.get("name") or "?"
        dist = dev.get("distance_km")
        dist_text = f"{dist * 1000:.0f} m" if dist is not None and dist < 1 else (
            f"{dist:.2f} km" if dist is not None else "?"
        )
        extra = dev.get("encryption") or dev.get("radio") or dev.get("product") or dev.get("brand") or ""
        line = f"  · {dist_text:>9} — {name} [{dev.get('type')}]"
        if ident:
            line += f" {ident}"
        if extra:
            line += f" ({extra})"
        lines.append(line)
    if result["count"] > top:
        lines.append(f"  … {result['count'] - top} more")

    if quiet_sources:
        lines.append("silent sources:")
        lines.extend(f"  - {s}" for s in quiet_sources)
    return "\n".join(lines)


def answer(message: str, creds=None, radius_km=None, limit=100, timeout=DEFAULT_TIMEOUT) -> dict:
    """Answer a free-form chat message with a coordinate-driven scan.

    This is a deterministic local analyst (no external LLM): it reads
    coordinates, a radius and the requested sources out of the message, queries
    the configured sources and reports exactly what came back — including the
    sources that stayed silent and why.
    """
    creds = creds or Credentials()
    text = (message or "").strip()
    if not text:
        return {"reply": "Send coordinates, e.g. `47.2066 27.7950 2km`, or a place name.", "data": {}}

    coords = extract_coordinates(text)
    place = ""
    if coords is None:
        candidate = _place_candidate(text)
        if candidate:
            found = geocode(candidate, timeout=timeout)
            if found.get("status") == "ok":
                coords = (found["lat"], found["lon"])
                place = found.get("display_name") or candidate
            else:
                reason = str(found.get("detail") or "")[:160]
                return {
                    "reply": (
                        f"No coordinates in your message and '{candidate}' could not be geocoded "
                        f"({found.get('status')}: {reason}).\n"
                        "Send decimal degrees instead, e.g. `47.2066 27.7950 2km`."
                    ),
                    "data": found,
                }
    if coords is None:
        return {
            "reply": (
                "I need a location. Send decimal degrees — `47.2066 27.7950` — optionally with a "
                "radius (`47.2066 27.7950 2km`) and a source (`wifi`, `bt`, `cell`, `iot`, "
                "`alpr`, `sdr`, `all`)."
            ),
            "data": {},
        }

    lat, lon = coords
    radius = radius_km if radius_km is not None else extract_radius_km(text, default=1.0)
    modes = detect_intents(text) or _ALL_MODES

    result = scan(lat, lon, radius_km=radius, modes=modes, creds=creds, limit=limit, timeout=timeout)
    if not place:
        rev = reverse_geocode(lat, lon, timeout=timeout)
        if rev.get("status") == "ok":
            place = rev.get("display_name") or ""

    reply = summarise_scan(result, place=place)
    if not any(src.get("status") == "ok" and src.get("count") for src in result["sources"]):
        reply += (
            "\n\nNothing to report at this point with the current configuration. "
            "Check keys with `config` / `wiretaper config` and reachability with `test`."
        )
    return {"reply": reply, "data": result}


_STOPWORDS = (
    "what", "whats", "what's", "is", "are", "the", "a", "an", "near", "nearby", "around",
    "show", "me", "find", "search", "scan", "within", "radius", "of", "at", "in", "km", "m",
    "что", "какие", "есть", "рядом", "около", "вокруг", "покажи", "найди", "в", "радиусе", "км",
    "метрах", "м", "сколько", "где", "which", "any", "devices", "networks",
)


def _place_candidate(text: str) -> str:
    """Best-effort place name from a message that contains no coordinates."""
    words = []
    for token in re.split(r"[^\w\u00c0-\uffff'-]+", text or ""):
        clean = token.strip("'-")
        if not clean:
            continue
        lowered = clean.lower()
        if lowered in _STOPWORDS or re.search(r"\d", lowered):
            continue
        if lowered in _INTENT_WORDS or any(low in _INTENT_WORDS for low in _INTENT_WORDS if low == lowered):
            continue
        words.append(clean)
    if not words:
        return ""
    return " ".join(words[:4])
