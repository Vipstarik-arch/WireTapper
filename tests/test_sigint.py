"""Offline test-suite for WireTapper's coordinate-driven core.

Nothing here touches the network: ``sigint.requests`` is swapped for a stub that
serves canned API payloads, and the local Flock datasets ship with the repo.
"""

import json
import os
import sqlite3
import sys

import pytest
import requests

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import cli  # noqa: E402
import sigint  # noqa: E402

# Real-world fixtures: downtown Akron (OH) — matches the bundled Pigvision.csv,
# and Chișinău/Ungheni (MD) — a place with no ALPR data at all.
AKRON = (41.0925, -81.5575)
UNGHENI = (47.2066, 27.7950)


# --------------------------------------------------------------------------- #
# HTTP stub
# --------------------------------------------------------------------------- #
class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text else ("" if payload is None else str(payload))

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


class FakeRequests:
    """Route table keyed by URL substring -> callable(params, kwargs) -> FakeResponse."""

    RequestException = requests.RequestException

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def _dispatch(self, method, url, params=None, **kwargs):
        self.calls.append({"method": method, "url": url, "params": params, "kwargs": kwargs})
        for needle, handler in self.routes.items():
            if needle in url:
                result = handler(params or {}, kwargs)
                if isinstance(result, Exception):
                    raise result
                return result
        return FakeResponse(404, text="no fake route configured")

    def get(self, url, params=None, **kwargs):
        return self._dispatch("GET", url, params, **kwargs)

    def post(self, url, params=None, **kwargs):
        return self._dispatch("POST", url, params, **kwargs)


@pytest.fixture
def stub_http(monkeypatch):
    def install(routes):
        fake = FakeRequests(routes)
        monkeypatch.setattr(sigint, "requests", fake)
        return fake

    return install


def creds_with(**values):
    """Credentials built purely from environment variables (no files involved)."""
    for key in sigint.Credentials.KEYS:
        os.environ.pop(key, None)
    os.environ.update(values)
    creds = sigint.Credentials(
        db_path="/nonexistent/credentials.db", env_path="/nonexistent/.env"
    )
    for key in values:
        os.environ.pop(key, None)
    return creds


EMPTY_CREDS = creds_with()


# --------------------------------------------------------------------------- #
# Geo helpers
# --------------------------------------------------------------------------- #
def test_haversine_known_distance():
    # Chișinău -> Ungheni is roughly 80 km in a straight line.
    dist = sigint.haversine_km(47.0105, 28.8638, 47.2066, 27.7950)
    assert 75 < dist < 90


def test_haversine_zero_and_symmetry():
    assert sigint.haversine_km(*AKRON, *AKRON) == 0
    assert sigint.haversine_km(1, 2, 3, 4) == pytest.approx(sigint.haversine_km(3, 4, 1, 2))


def test_bounding_box_corrects_longitude_for_latitude():
    lat_min, lat_max, lon_min, lon_max = sigint.bounding_box(60.0, 25.0, 11.1)
    assert lat_max - lat_min == pytest.approx(0.2, abs=1e-6)  # ~11.1 km of latitude
    # At 60°N a longitude degree is ~half as wide, so the box must be ~twice as tall.
    assert (lon_max - lon_min) > (lat_max - lat_min) * 1.8


def test_bounding_box_at_equator_is_square():
    lat_min, lat_max, lon_min, lon_max = sigint.bounding_box(0.0, 0.0, 11.1)
    assert (lat_max - lat_min) == pytest.approx(lon_max - lon_min, rel=1e-6)


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #
def test_credentials_ignore_placeholders(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "WIGLE_API_NAME=your_wigle_api_name\n"
        "WIGLE_API_TOKEN=real-token-value\n"
        "# comment line\n"
        "\n"
        "SHODAN_API_KEY=\n"
    )
    creds = sigint.Credentials(db_path=str(tmp_path / "none.db"), env_path=str(env))
    assert not creds.has("WIGLE_API_NAME")       # placeholder == not configured
    assert creds.get("WIGLE_API_TOKEN") == "real-token-value"
    assert creds.origin("WIGLE_API_TOKEN") == ".env"
    assert not creds.has("SHODAN_API_KEY")        # empty == not configured
    assert not creds.wigle_ready()                # needs both name and token


def test_credentials_prefer_sqlite_over_env_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SHODAN_API_KEY=from-env-file\n")
    db = tmp_path / "credentials.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE credentials (key TEXT PRIMARY KEY, value TEXT, updated_at TIMESTAMP)"
        )
        conn.execute(
            "INSERT INTO credentials (key, value) VALUES ('SHODAN_API_KEY', 'from-db')"
        )
    creds = sigint.Credentials(db_path=str(db), env_path=str(env))
    assert creds.get("SHODAN_API_KEY") == "from-db"
    assert creds.origin("SHODAN_API_KEY") == "credentials.db"


def test_credentials_report_masks_secrets(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SHODAN_API_KEY=abcdefgh12345678\n")
    creds = sigint.Credentials(db_path=str(tmp_path / "none.db"), env_path=str(env))
    row = next(r for r in creds.report() if r["key"] == "SHODAN_API_KEY")
    assert row["configured"] is True
    assert "abcdefgh12345678" not in row["masked"]
    assert row["masked"].startswith("abcd")
    assert "len 16" in row["masked"]


def test_save_credential_roundtrip(tmp_path, monkeypatch):
    db = tmp_path / "credentials.db"
    monkeypatch.setattr(sigint, "DB_PATH", str(db))
    assert cli.save_credential("SHODAN_API_KEY", "written-by-cli", db_path=str(db))
    creds = sigint.Credentials(db_path=str(db), env_path=str(tmp_path / "none.env"))
    assert creds.get("SHODAN_API_KEY") == "written-by-cli"
    with pytest.raises(KeyError):
        cli.save_credential("NOT_A_WIRETAPPER_KEY", "x", db_path=str(db))


# --------------------------------------------------------------------------- #
# Classification + SDR hardware probe
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "name,expected",
    [
        ("Tesla Model 3", "car"),
        ("HIKVISION Cam", "camera"),
        ("70MAI Dash Cam Pro", "dashcam"),
        ("AirPods Pro", "headphone"),
        ("Sony BRAVIA TV", "tv"),
        ("RTL-SDR Blog V4", "sdr"),
        ("Fitbit Charge 5", "iot"),
        ("CafeGuestWiFi", "router"),
        ("", "router"),
        (None, "router"),
    ],
)
def test_classify_device(name, expected):
    assert sigint.classify_device(name, "router") == expected


def test_detect_sdr_when_nothing_attached(tmp_path):
    info = sigint.detect_sdr(usb_dir=str(tmp_path / "missing"))
    assert info["connected"] is False
    assert info["status"] == "Disconnected"


def test_detect_sdr_finds_rtlsdr_via_fake_sysfs(tmp_path):
    dev = tmp_path / "usb" / "1-2"
    dev.mkdir(parents=True)
    (dev / "idVendor").write_text("0bda\n")
    (dev / "idProduct").write_text("2838\n")
    (dev / "product").write_text("RTL2838UHIDIR\n")
    info = sigint.detect_sdr(usb_dir=str(tmp_path / "usb"))
    assert info["connected"] is True
    assert info["frequency_range"] == "500 kHz - 1766 MHz"
    assert "RTL2838UHIDIR" in info["device"]


def test_detect_sdr_finds_hackrf_via_fake_sysfs(tmp_path):
    dev = tmp_path / "usb" / "2-1"
    dev.mkdir(parents=True)
    (dev / "idVendor").write_text("1d50")
    (dev / "idProduct").write_text("6089")
    (dev / "product").write_text("HackRF One")
    info = sigint.detect_sdr(usb_dir=str(tmp_path / "usb"))
    assert info["connected"] is True
    assert "HackRF" in info["device"]
    assert info["frequency_range"] == "1 MHz - 6 GHz"


# --------------------------------------------------------------------------- #
# WiGLE
# --------------------------------------------------------------------------- #
WIGLE_NETWORKS = {
    "success": True,
    "results": [
        {  # far away -> must be sorted after the closer one
            "ssid": "FarRouter", "netid": "aa:bb:cc:00:00:01", "trilat": 41.10,
            "trilong": -81.56, "level": -80, "channel": 6, "encryption": "wpa2",
            "lastupdt": "2026-01-01", "vendor": "Netgear",
        },
        {
            "ssid": "TeslaCam", "netid": "aa:bb:cc:00:00:02", "trilat": 41.0926,
            "trilong": -81.5576, "level": -44, "channel": 11, "encryption": "wpa3",
            "lastupdt": "2026-02-01", "vendor": None,
        },
        {  # no coordinates -> must be dropped, not plotted at 0,0
            "ssid": "NoCoords", "netid": "aa:bb:cc:00:00:03", "trilat": None,
            "trilong": None,
        },
        {  # string coordinates -> must be coerced
            "ssid": "StringCoords", "netid": "aa:bb:cc:00:00:04", "trilat": "41.0930",
            "trilong": "-81.5580", "level": "-61",
        },
    ],
}


def test_wigle_wifi_normalises_sorts_and_distances(stub_http):
    stub_http({"api.wigle.net": lambda params, kw: FakeResponse(200, WIGLE_NETWORKS)})
    creds = creds_with(WIGLE_API_NAME="user", WIGLE_API_TOKEN="tok")
    res = sigint.wigle_wifi(AKRON[0], AKRON[1], radius_km=1.0, creds=creds)

    assert res["status"] == "ok"
    assert res["count"] == 3                      # the coordinate-less row is dropped
    assert res["devices"][0]["ssid"] == "TeslaCam"
    assert res["devices"][0]["distance_km"] < res["devices"][-1]["distance_km"]
    assert res["devices"][0]["type"] == "car"     # classify_device kicked in
    assert res["devices"][0]["encryption"] == "wpa3"
    assert all(d["source"] == "wigle" for d in res["devices"])


def test_wigle_request_uses_bounding_box_and_basic_auth(stub_http):
    fake = stub_http({"api.wigle.net": lambda params, kw: FakeResponse(200, {"results": []})})
    creds = creds_with(WIGLE_API_NAME="user", WIGLE_API_TOKEN="tok")
    sigint.wigle_wifi(47.2066, 27.7950, radius_km=2.0, creds=creds)

    call = fake.calls[0]
    assert call["url"].endswith("/api/v2/network/search")
    assert call["kwargs"]["auth"] == ("user", "tok")
    assert call["params"]["latrange1"] < 47.2066 < call["params"]["latrange2"]
    assert call["params"]["longrange1"] < 27.7950 < call["params"]["longrange2"]


def test_wigle_skipped_without_key(stub_http):
    fake = stub_http({"api.wigle.net": lambda params, kw: FakeResponse(200, WIGLE_NETWORKS)})
    res = sigint.wigle_wifi(*AKRON, creds=EMPTY_CREDS)
    assert res["status"] == "skipped"
    assert res["devices"] == []
    assert fake.calls == []            # never called the API without credentials


def test_wigle_reports_auth_and_rate_limit_failures(stub_http):
    stub_http({"api.wigle.net": lambda params, kw: FakeResponse(401, text="denied")})
    res = sigint.wigle_wifi(*AKRON, creds=creds_with(WIGLE_API_NAME="u", WIGLE_API_TOKEN="t"))
    assert res["status"] == "error" and "401" in res["detail"]

    stub_http({"api.wigle.net": lambda params, kw: FakeResponse(429, text="slow down")})
    res = sigint.wigle_wifi(*AKRON, creds=creds_with(WIGLE_API_NAME="u", WIGLE_API_TOKEN="t"))
    assert res["status"] == "error" and "429" in res["detail"]


def test_wigle_reports_network_failure(stub_http):
    stub_http({"api.wigle.net": lambda params, kw: requests.ConnectionError("dns blocked")})
    res = sigint.wigle_wifi(*AKRON, creds=creds_with(WIGLE_API_NAME="u", WIGLE_API_TOKEN="t"))
    assert res["status"] == "error"
    assert res["devices"] == []
    assert "unreachable" in res["detail"]


def test_wigle_bluetooth_and_cell(stub_http):
    stub_http(
        {
            "bluetooth/search": lambda params, kw: FakeResponse(
                200,
                {"results": [{"name": "AirPods", "netid": "de:ad:be:ef:00:01",
                              "trilat": 41.0926, "trilong": -81.5576, "level": -55,
                              "type": "BLE", "lastupdt": "2026-03-01"}]},
            ),
            "cell/search": lambda params, kw: FakeResponse(
                200,
                {"results": [{"id": "12345", "gentype": "LTE", "trilat": 41.095,
                              "trilong": -81.56, "road": "Main St", "qos": 3,
                              "lastupdt": "2026-03-02"}]},
            ),
        }
    )
    creds = creds_with(WIGLE_API_NAME="u", WIGLE_API_TOKEN="t")
    bt = sigint.wigle_bluetooth(*AKRON, creds=creds)
    assert bt["status"] == "ok" and bt["devices"][0]["type"] == "headphone"

    cell = sigint.wigle_cell(*AKRON, creds=creds)
    assert cell["status"] == "ok"
    assert cell["devices"][0]["type"] == "cell_tower"
    assert cell["devices"][0]["cell_id"] == "12345"
    assert "[LTE]" in cell["devices"][0]["ssid"]


# --------------------------------------------------------------------------- #
# Shodan / Censys
# --------------------------------------------------------------------------- #
SHODAN_PAYLOAD = {
    "total": 3,
    "matches": [
        {
            "ip_str": "203.0.113.7", "port": 554, "product": "RTSP camera",
            "org": "Example ISP", "timestamp": "2026-04-01T10:00:00",
            "data": "RTSP/1.0 200 OK", "location": {"latitude": 41.093, "longitude": -81.558},
        },
        {
            "ip_str": "203.0.113.9", "port": 80, "product": "nginx",
            "isp": "Other ISP", "data": "HTTP/1.1 200 OK",
            "location": {"latitude": 41.20, "longitude": -81.70},
        },
        {  # no coordinates -> must be dropped
            "ip_str": "203.0.113.11", "port": 22, "product": "OpenSSH",
            "location": {},
        },
    ],
}


def test_shodan_normalises_and_classifies_cameras(stub_http):
    stub_http({"api.shodan.io": lambda params, kw: FakeResponse(200, SHODAN_PAYLOAD)})
    res = sigint.shodan_geo(*AKRON, radius_km=5, creds=creds_with(SHODAN_API_KEY="k"))
    assert res["status"] == "ok"
    assert res["count"] == 2
    assert res["devices"][0]["type"] == "camera"     # port 554 / RTSP
    assert res["devices"][0]["ip"] == "203.0.113.7"
    assert res["devices"][0]["distance_km"] < res["devices"][1]["distance_km"]


def test_shodan_query_uses_geo_filter_and_key(stub_http):
    fake = stub_http({"api.shodan.io": lambda params, kw: FakeResponse(200, {"matches": []})})
    sigint.shodan_geo(47.2066, 27.7950, radius_km=3, creds=creds_with(SHODAN_API_KEY="secret"))
    params = fake.calls[0]["params"]
    assert params["key"] == "secret"
    kind, qlat, qlon, qradius = params["query"].split(":")[0], *params["query"].split(":")[1].split(",")
    assert kind == "geo"
    assert (float(qlat), float(qlon), float(qradius)) == (47.2066, 27.7950, 3.0)


def test_shodan_skipped_without_key_and_reports_api_error(stub_http):
    fake = stub_http({"api.shodan.io": lambda params, kw: FakeResponse(200, SHODAN_PAYLOAD)})
    res = sigint.shodan_geo(*AKRON, creds=EMPTY_CREDS)
    assert res["status"] == "skipped" and fake.calls == []

    stub_http({"api.shodan.io": lambda params, kw: FakeResponse(401, {"error": "Invalid API key"})})
    res = sigint.shodan_geo(*AKRON, creds=creds_with(SHODAN_API_KEY="bad"))
    assert res["status"] == "error" and "Invalid API key" in res["detail"]


CENSYS_PAYLOAD = {
    "result": {
        "hits": [
            {
                "ip": "198.51.100.4",
                "services": [{"port": 8000, "service_name": "HTTP"}],
                "autonomous_system": {"name": "Example AS"},
                "location": {"coordinates": {"latitude": 41.0928, "longitude": -81.5578}},
            },
            {
                "ip": "198.51.100.5",
                "services": [{"port": 443, "service_name": "HTTPS"}],
                "location": {"coordinates": {}},   # dropped
            },
        ]
    }
}


def test_censys_normalises_and_skips_coordinateless_hosts(stub_http):
    stub_http({"search.censys.io": lambda params, kw: FakeResponse(200, CENSYS_PAYLOAD)})
    creds = creds_with(CENSYS_API_ID="id", CENSYS_API_SECRET="secret")
    res = sigint.censys_geo(*AKRON, creds=creds)
    assert res["status"] == "ok" and res["count"] == 1
    dev = res["devices"][0]
    assert dev["ip"] == "198.51.100.4"
    assert dev["type"] == "camera"        # port 8000 is treated as a camera service
    assert "Example AS" in dev["vendor"]


def test_censys_sends_basic_auth_and_range_query(stub_http):
    fake = stub_http({"search.censys.io": lambda params, kw: FakeResponse(200, {"result": {"hits": []}})})
    sigint.censys_geo(47.2066, 27.7950, radius_km=2,
                      creds=creds_with(CENSYS_API_ID="id", CENSYS_API_SECRET="secret"))
    call = fake.calls[0]
    assert call["kwargs"]["auth"] == ("id", "secret")
    assert "location.coordinates.latitude:" in call["params"]["q"]
    assert "location.coordinates.longitude:" in call["params"]["q"]


def test_scan_iot_combines_both_engines(stub_http):
    stub_http(
        {
            "api.shodan.io": lambda params, kw: FakeResponse(200, SHODAN_PAYLOAD),
            "search.censys.io": lambda params, kw: FakeResponse(200, CENSYS_PAYLOAD),
        }
    )
    creds = creds_with(SHODAN_API_KEY="k", CENSYS_API_ID="id", CENSYS_API_SECRET="s")
    res = sigint.scan_iot(*AKRON, radius_km=5, creds=creds)
    assert res["status"] == "ok"
    assert res["count"] == 3
    assert {d["source"] for d in res["devices"]} == {"shodan", "censys"}


def test_scan_iot_all_disabled_is_skipped(stub_http):
    stub_http({})
    res = sigint.scan_iot(*AKRON, creds=EMPTY_CREDS, use_shodan=False, use_censys=False)
    assert res["status"] == "skipped" and res["devices"] == []


def test_scan_iot_category_filter(stub_http):
    stub_http({"api.shodan.io": lambda params, kw: FakeResponse(200, SHODAN_PAYLOAD)})
    creds = creds_with(SHODAN_API_KEY="k")
    res = sigint.scan_iot(*AKRON, creds=creds, use_censys=False, category="camera")
    assert res["count"] == 1 and res["devices"][0]["type"] == "camera"


# --------------------------------------------------------------------------- #
# OpenCellID
# --------------------------------------------------------------------------- #
def test_opencellid_primary_endpoint(stub_http):
    stub_http(
        {
            "getInArea": lambda params, kw: FakeResponse(
                200,
                [{"lat": 41.093, "lon": -81.558, "radio": "LTE", "cellid": 991,
                  "mcc": 310, "mnc": 410, "lac": 12, "signal": -71, "updated": "2026"}],
            )
        }
    )
    res = sigint.opencellid_towers(*AKRON, creds=creds_with(OPENCELLID_API_KEY="k"))
    assert res["status"] == "ok" and res["count"] == 1
    assert res["devices"][0]["radio"] == "LTE"
    assert res["devices"][0]["type"] == "cell_tower"


def test_opencellid_falls_back_to_public_ajax_feed(stub_http):
    fake = stub_http(
        {
            "getInArea": lambda params, kw: FakeResponse(403, text="bad key"),
            "getCells.php": lambda params, kw: FakeResponse(
                200,
                {"features": [
                    {"geometry": {"coordinates": [-81.5578, 41.0926]},
                     "properties": {"radio": "UMTS", "cellid": 7, "mcc": 310, "net": 410,
                                    "area": 12, "updated": "2026"}},
                ]},
            ),
        }
    )
    res = sigint.opencellid_towers(*AKRON, creds=creds_with(OPENCELLID_API_KEY="bad"))
    assert res["status"] == "ok" and res["count"] == 1
    assert "ajax getCells" in res["detail"]
    # bbox must be lon,lat ordered for the OpenCellID ajax endpoint
    assert fake.calls[-1]["params"]["bbox"].startswith("-81.")


def test_opencellid_without_key_still_tries_public_feed(stub_http):
    fake = stub_http({"getCells.php": lambda params, kw: FakeResponse(200, {"features": []})})
    res = sigint.opencellid_towers(*AKRON, creds=EMPTY_CREDS)
    assert res["status"] == "empty"                       # answered, but nothing there
    assert "OPENCELLID_API_KEY not configured" in res["detail"]
    assert fake.calls and "getCells.php" in fake.calls[0]["url"]


def test_opencellid_reports_broken_upstream_as_error(stub_http):
    stub_http({"getCells.php": lambda params, kw: FakeResponse(500, text="boom")})
    res = sigint.opencellid_towers(*AKRON, creds=EMPTY_CREDS)
    assert res["status"] == "error"                       # not silently "empty"
    assert res["devices"] == []


# --------------------------------------------------------------------------- #
# Geocoding
# --------------------------------------------------------------------------- #
def test_geocode_and_reverse_geocode(stub_http):
    stub_http(
        {
            "/search": lambda params, kw: FakeResponse(
                200, [{"lat": "47.2066", "lon": "27.7950", "display_name": "Ungheni, Moldova",
                       "boundingbox": ["47.1", "47.3", "27.7", "27.9"]}]
            ),
            "/reverse": lambda params, kw: FakeResponse(
                200, {"display_name": "Ungheni, Raionul Ungheni, Moldova",
                      "address": {"city": "Ungheni", "country": "Moldova"}}
            ),
        }
    )
    found = sigint.geocode("Ungheni")
    assert found["status"] == "ok" and found["lat"] == 47.2066

    back = sigint.reverse_geocode(47.2066, 27.7950)
    assert back["status"] == "ok"
    assert back["address"]["country"] == "Moldova"


def test_geocode_handles_empty_and_not_found(stub_http):
    assert sigint.geocode("   ")["status"] == "error"
    stub_http({"/search": lambda params, kw: FakeResponse(200, [])})
    assert sigint.geocode("Nowhere")["status"] == "empty"


# --------------------------------------------------------------------------- #
# Offline sources: Flock / ALPR datasets
# --------------------------------------------------------------------------- #
def test_flock_near_finds_real_bundled_cameras():
    res = sigint.flock_near(*AKRON, radius_km=1.0)
    if res["status"] == "error":  # datasets not shipped in this checkout
        pytest.skip("no local Flock datasets available")
    assert res["status"] == "ok"
    assert res["count"] > 0
    nearest = res["devices"][0]
    assert nearest["distance_km"] <= 1.0
    assert nearest["type"] == "alpr_camera"
    assert nearest["lat"] and nearest["lon"]
    assert res["devices"] == sorted(res["devices"], key=lambda d: d["distance_km"])


def test_flock_near_respects_the_radius():
    small = sigint.flock_near(*AKRON, radius_km=0.2)
    large = sigint.flock_near(*AKRON, radius_km=5.0)
    assert small["count"] <= large["count"]
    assert all(d["distance_km"] <= 0.2 for d in small["devices"])


def test_flock_near_returns_nothing_for_places_without_data():
    res = sigint.flock_near(*UNGHENI, radius_km=50.0)
    assert res["status"] == "empty"
    assert res["devices"] == []      # honest empty answer, not invented cameras


def test_flock_datasets_lists_local_files():
    res = sigint.flock_datasets()
    assert res["status"] == "ok"
    assert any(d.get("is_downloaded") for d in res["datasets"])


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def test_scan_merges_sources_and_deduplicates(stub_http):
    stub_http(
        {
            "api.wigle.net": lambda params, kw: FakeResponse(200, WIGLE_NETWORKS),
            "api.shodan.io": lambda params, kw: FakeResponse(200, SHODAN_PAYLOAD),
            "search.censys.io": lambda params, kw: FakeResponse(200, CENSYS_PAYLOAD),
            "getCells.php": lambda params, kw: FakeResponse(200, {"features": []}),
        }
    )
    creds = creds_with(WIGLE_API_NAME="u", WIGLE_API_TOKEN="t", SHODAN_API_KEY="k",
                       CENSYS_API_ID="id", CENSYS_API_SECRET="s")
    res = sigint.scan(*AKRON, radius_km=2.0, modes=("wifi", "iot"), creds=creds)

    assert res["count"] == len(res["devices"]) > 0
    assert {s["source"] for s in res["sources"]} == {"wigle_wifi", "iot"}
    assert res["devices"] == sorted(res["devices"], key=lambda d: d.get("distance_km", 0))
    keys = [(d.get("lat"), d.get("lon"), d.get("bssid") or d.get("ip")) for d in res["devices"]]
    assert len(keys) == len(set(keys))    # merged list is de-duplicated


def test_scan_without_keys_reports_every_source_honestly(stub_http):
    fake = stub_http({"api.": lambda params, kw: FakeResponse(200, {"results": []})})
    res = sigint.scan(*UNGHENI, radius_km=2.0,
                      modes=("wifi", "bluetooth", "cell", "iot", "flock", "sdr"),
                      creds=EMPTY_CREDS)
    assert res["devices"] == []           # no key + no data -> nothing invented
    statuses = {s["source"]: s["status"] for s in res["sources"]}
    assert statuses["wigle_wifi"] == "skipped"
    assert statuses["wigle_bluetooth"] == "skipped"
    assert statuses["wigle_cell"] == "skipped"
    assert statuses["iot"] == "skipped"           # shodan + censys both unconfigured
    assert statuses["sdr"] in ("ok", "empty")
    assert statuses["flock"] in ("ok", "empty", "error")
    assert all(s["count"] == 0 for s in res["sources"] if s["status"] == "skipped")

    iot = next(s for s in res["sources"] if s["source"] == "iot")
    nested = {n["source"]: n["status"] for n in iot["sources"]}
    assert nested == {"shodan": "skipped", "censys": "skipped"}


def test_scan_unknown_mode_is_reported_not_crashing(stub_http):
    stub_http({})
    res = sigint.scan(*AKRON, modes=("nonsense",), creds=EMPTY_CREDS)
    assert res["sources"][0]["status"] == "skipped"
    assert res["devices"] == []


def test_sdr_probe_never_returns_devices(stub_http):
    stub_http({})
    res = sigint.scan(*AKRON, modes=("sdr",), creds=EMPTY_CREDS)
    sdr = next(s for s in res["sources"] if s["source"] == "sdr")
    assert sdr["devices"] == []
    assert "no RF capture" in sdr["detail"]
    assert sdr["sdr_status"]["device"]


def test_import_telemetry_preview():
    path = os.path.join(REPO_ROOT, "uploads", "flock", "Flock_Master_Registry.csv")
    if not os.path.exists(path):
        pytest.skip("bundled telemetry sample missing")
    res = sigint.import_telemetry(path)
    assert res["status"] == "success"
    assert res["total_rows"] > 100
    assert res["detected_mappings"]["lat"] == "trilat"
    assert res["detected_mappings"]["lon"] == "trilong"
    assert sigint.import_telemetry("/does/not/exist.csv")["status"] == "error"


# --------------------------------------------------------------------------- #
# CLI parsing / chat REPL
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "line,expected",
    [
        ("47.2066 27.7950", (47.2066, 27.7950, None)),
        ("47.2066,27.7950", (47.2066, 27.7950, None)),
        ("47.2066, 27.7950 2km", (47.2066, 27.7950, "2km")),
        ("47.2066N 27.7950E 500m", (47.2066, 27.7950, "500m")),
        ("-47.2066 -27.7950", (-47.2066, -27.7950, None)),
    ],
)
def test_parse_coordinates(line, expected):
    assert cli.parse_coordinates(line) == expected


def test_parse_coordinates_rejects_nonsense():
    with pytest.raises(ValueError):
        cli.parse_coordinates("hello world")
    with pytest.raises(ValueError):
        cli.parse_coordinates("95.0 10.0")      # latitude out of range


@pytest.mark.parametrize("token,expected", [("500m", 0.5), ("2km", 2.0), ("3", 3.0), ("1mi", 1.609344)])
def test_parse_radius(token, expected):
    assert cli.parse_radius(token) == pytest.approx(expected)


def test_parse_command_routes_chat_lines():
    state = {"mode": "all", "radius": 1.0}
    assert cli.parse_command("quit", state)["action"] == "quit"
    assert cli.parse_command("help", state)["action"] == "help"
    assert cli.parse_command("", state)["action"] == "noop"
    assert cli.parse_command("json on", state) == {"action": "set_json", "value": "on"}
    assert cli.parse_command("radius 2km", state)["action"] == "set_radius"
    assert cli.parse_command("where 47.2 27.8", state)["action"] == "reverse_geocode"
    assert cli.parse_command("find Ungheni Moldova", state) == {
        "action": "geocode", "query": "Ungheni Moldova"
    }
    assert cli.parse_command("config", state)["action"] == "config"
    assert cli.parse_command("set SHODAN_API_KEY abc", state)["key"] == "SHODAN_API_KEY"

    scan = cli.parse_command("wifi 47.2066 27.7950 2km", state)
    assert scan["action"] == "scan" and scan["modes"] == ("wifi",)
    assert (scan["lat"], scan["lon"], scan["radius"]) == (47.2066, 27.7950, 2.0)

    bare = cli.parse_command("47.2066 27.7950", state)
    assert bare["modes"] == cli.MODE_ALIASES["all"]
    assert bare["radius"] == 1.0

    # anything that is not a command goes to the local analyst
    ask = cli.parse_command("what is around Ungheni", state)
    assert ask["action"] == "answer" and ask["message"] == "what is around Ungheni"
    assert cli.parse_command("ask wifi near 47.2 27.8", state) == {
        "action": "answer", "message": "wifi near 47.2 27.8"
    }
    assert cli.parse_command("ask", state)["action"] == "error"


def test_execute_handles_settings_without_network():
    state = {"creds": EMPTY_CREDS, "mode": "all", "radius": 1.0, "limit": 100}
    assert "json output: on" in cli.execute({"action": "set_json", "value": "on"}, state)
    assert state["json"] is True
    assert "default radius" in cli.execute({"action": "set_radius", "value": "500m"}, state)
    assert state["radius"] == 0.5
    assert cli.execute({"action": "set_radius", "value": "banana"}, state).startswith("!")
    assert "unknown mode" in cli.execute({"action": "set_mode", "value": "nope"}, state)
    assert "WIGLE_API_TOKEN" in cli.execute({"action": "config"}, state)
    assert cli.execute({"action": "help"}, state).startswith("WireTapper chat mode")
    assert cli.execute({"action": "rescan"}, state).startswith("! no previous coordinates")
    assert cli.execute({"action": "quit"}, state) == "bye" and state["quit"] is True


def test_chat_repl_end_to_end_offline(stub_http):
    stub_http({})  # every network call fails; only local data can answer
    lines = iter(["mode flock", f"{AKRON[0]} {AKRON[1]} 1km", "sdr", "quit"])
    written = []
    cli.chat(
        creds=EMPTY_CREDS,
        banner=False,
        input_fn=lambda prompt="": next(lines),
        output_fn=written.append,
    )
    text = "\n".join(written)
    assert "alpr_camera" in text or "no devices" in text
    assert "bye" in text


def test_chat_repl_survives_an_exception(stub_http):
    stub_http({})
    lines = iter(["find Ungheni", "quit"])
    written = []

    def boom(*args, **kwargs):
        raise RuntimeError("kaboom")

    import sigint as _sig
    original = _sig.geocode
    _sig.geocode = boom
    try:
        cli.chat(creds=EMPTY_CREDS, banner=False,
                 input_fn=lambda prompt="": next(lines), output_fn=written.append)
    finally:
        _sig.geocode = original
    assert any("kaboom" in line for line in written)


# --------------------------------------------------------------------------- #
# CLI entry point
# --------------------------------------------------------------------------- #
def test_main_flock_command_prints_table(capsys):
    rc = cli.main(["flock", "--lat", str(AKRON[0]), "--lon", str(AKRON[1]), "--radius", "1km"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ALPR/Flock cameras" in out


def test_main_requires_coordinates(capsys):
    with pytest.raises(SystemExit):
        cli.main(["flock", "--radius", "1km"])


def test_main_sdr_json(capsys):
    rc = cli.main(["sdr", "--json"])
    payload = __import__("json").loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["connected"] in (True, False)
    assert "device" in payload


def test_main_config_lists_all_keys(capsys):
    cli.main(["config"])
    out = capsys.readouterr().out
    for key in sigint.Credentials.KEYS:
        assert key in out


def test_parser_rejects_unknown_mode():
    with pytest.raises(SystemExit):
        cli._modes_from("wimax")


# --------------------------------------------------------------------------- #
# Local analyst (free-form chat -> coordinate scan)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "text,expected",
    [
        ("47.2066 27.7950", (47.2066, 27.7950)),
        ("что вокруг 47.2066, 27.7950 в радиусе 2 км", (47.2066, 27.7950)),
        ("scan 41.0925, -81.5575 within 500m", (41.0925, -81.5575)),
        ("47.2066N 27.7950E", (47.2066, 27.7950)),
        ("47.2066S 27.7950W", (-47.2066, -27.7950)),
        ("47°12.4'N 27°47.7'E", (pytest.approx(47.20667, abs=1e-4), pytest.approx(27.795, abs=1e-4))),
        ('47°12\'23.8"N 27°47\'42.0"E', (pytest.approx(47.20661, abs=1e-4), pytest.approx(27.795, abs=1e-4))),
        ("no coordinates here", None),
        ("999.0 999.0", None),
    ],
)
def test_extract_coordinates(text, expected):
    assert sigint.extract_coordinates(text) == expected


def test_dms_text_is_never_parsed_as_decimal():
    # A half-understood degree string must not silently become wrong decimals.
    assert sigint.extract_coordinates("47°12.4") is None


@pytest.mark.parametrize(
    "text,expected",
    [("2km", 2.0), ("в радиусе 500 м", 0.5), ("within 3 km", 3.0),
     ("1mi", 1.609344), ("no radius given", 1.0)],
)
def test_extract_radius_km(text, expected):
    assert sigint.extract_radius_km(text) == pytest.approx(expected)


def test_detect_intents():
    assert sigint.detect_intents("show me the wifi networks") == ("wifi",)
    assert set(sigint.detect_intents("bluetooth и сотовые вышки")) == {"bluetooth", "cell"}
    assert sigint.detect_intents("alpr plate readers") == ("flock",)
    assert sigint.detect_intents("всё вокруг меня") == sigint.MODES
    assert sigint.detect_intents("47.2 27.8") == ()      # no intent -> caller decides


def test_place_candidate_skips_noise_words():
    assert sigint._place_candidate("what wifi is near Ungheni Moldova") == "Ungheni Moldova"
    assert sigint._place_candidate("wifi 2km") == ""


def test_summarise_scan_reports_counts_and_silence():
    result = {
        "lat": 41.0925, "lon": -81.5575, "radius_km": 1.0, "count": 2,
        "devices": [
            {"lat": 41.0926, "lon": -81.5576, "distance_km": 0.011, "ssid": "NearCam",
             "type": "alpr_camera", "id": "cam-1", "brand": "Flock Camera"},
            {"lat": 41.093, "lon": -81.558, "distance_km": 0.9, "ssid": "FarAP",
             "type": "router", "bssid": "aa:bb:cc:dd:ee:ff", "encryption": "wpa3"},
        ],
        "sources": [
            {"source": "flock", "status": "ok", "count": 2, "detail": "scanned Pigvision.csv:146"},
            {"source": "wigle_wifi", "status": "skipped", "count": 0, "detail": "no key"},
        ],
    }
    text = sigint.summarise_scan(result, place="Akron, OH")
    assert "41.0925, -81.5575" in text
    assert "Akron, OH" in text
    assert "flock: 2" in text
    assert "NearCam" in text and "11 m" in text
    assert "FarAP" in text and "aa:bb:cc:dd:ee:ff" in text and "wpa3" in text
    assert "wigle_wifi (skipped): no key" in text


def test_answer_uses_coordinates_and_honours_intent(stub_http):
    stub_http({})   # every API call fails; only local data can answer
    res = sigint.answer("alpr cameras near 41.0925 -81.5575 within 1km", creds=EMPTY_CREDS)
    assert res["data"]["lat"] == 41.0925
    assert res["data"]["radius_km"] == 1.0
    assert {s["source"] for s in res["data"]["sources"]} == {"flock"}
    assert res["data"]["count"] > 0
    assert "alpr_camera" in res["reply"]


def test_answer_falls_back_to_every_source(stub_http):
    stub_http({})
    res = sigint.answer("41.0925 -81.5575", creds=EMPTY_CREDS)
    sources = {s["source"] for s in res["data"]["sources"]}
    assert {"wigle_wifi", "wigle_bluetooth", "wigle_cell", "iot", "flock", "sdr"} <= sources


def test_answer_geocodes_a_place_name(stub_http):
    stub_http(
        {
            "nominatim": lambda params, kw: FakeResponse(
                200, [{"lat": "41.0925", "lon": "-81.5575", "display_name": "Akron, Ohio, USA"}]
            )
        }
    )
    res = sigint.answer("alpr around Akron Ohio 1km", creds=EMPTY_CREDS)
    assert res["data"]["lat"] == 41.0925
    assert "Akron, Ohio, USA" in res["reply"]


def test_answer_explains_itself_without_a_location(stub_http):
    stub_http({"nominatim": lambda params, kw: FakeResponse(200, [])})
    res = sigint.answer("hello", creds=EMPTY_CREDS)
    assert res["data"] in ({}, None) or "data" in res
    assert "coordinates" in res["reply"].lower()


def test_answer_rejects_empty_message(stub_http):
    stub_http({})
    assert "coordinates" in sigint.answer("   ", creds=EMPTY_CREDS)["reply"].lower()


def test_answer_tells_the_truth_when_nothing_answers(stub_http):
    stub_http({})
    res = sigint.answer("wifi near 47.2066 27.7950 2km", creds=EMPTY_CREDS)
    assert res["data"]["devices"] == []
    assert "no source returned data" in res["reply"].lower()
    assert "silent sources" in res["reply"].lower()
    assert "not configured" in res["reply"]


def test_chat_analyst_fallback_is_used_by_the_repl(stub_http):
    stub_http({})
    lines = iter(["what alpr cameras are near 41.0925 -81.5575 within 1km", "quit"])
    written = []
    cli.chat(creds=EMPTY_CREDS, banner=False,
             input_fn=lambda prompt="": next(lines), output_fn=written.append)
    text = "\n".join(written)
    assert "alpr_camera" in text
    assert "41.0925, -81.5575" in text


# --------------------------------------------------------------------------- #
# Place queries: region / bbox / zip prefix / city / export
# --------------------------------------------------------------------------- #
PBC_BBOX = "26.24,-80.90,27.05,-79.98"   # Palm Beach County, Florida


def test_parse_bbox():
    assert sigint.parse_bbox(PBC_BBOX) == (26.24, -80.90, 27.05, -79.98)
    assert sigint.parse_bbox("") is None
    assert sigint.parse_bbox(None) is None


@pytest.mark.parametrize("bad", ["1,2,3", "a,b,c,d", "27.0,-80.9,26.2,-80.0", "95,0,96,1", "1,2,3,4,5"])
def test_parse_bbox_rejects_garbage(bad):
    with pytest.raises(ValueError):
        sigint.parse_bbox(bad)


@pytest.mark.parametrize(
    "text,expected",
    [("Florida", "FL"), ("fl", "FL"), ("FL,", "FL"), ("", ""), ("Palm Beach", ""),
     ("new york", "NY"), ("Kaliningrad", "")],
)
def test_normalise_region(text, expected):
    assert sigint.normalise_region(text) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Palm Beach Florida", ("Palm Beach", "FL")),
        ("west palm beach fl", ("west palm beach", "FL")),
        ("Akron", ("Akron", "")),
        ("new york city ny", ("new york city", "NY")),
        ("", ("", "")),
    ],
)
def test_split_place_state(text, expected):
    assert sigint.split_place_state(text) == expected


def test_flock_search_by_region_and_bbox():
    res = sigint.flock_search(region="FL", bbox=PBC_BBOX)
    if res["status"] == "error":
        pytest.skip("no local Flock datasets")
    assert res["count"] > 0
    for cam in res["devices"]:
        assert 26.24 <= cam["lat"] <= 27.05
        assert -80.90 <= cam["lon"] <= -79.98
        assert cam["region"] in ("FL", "")     # rows without a region are kept, others dropped
    assert res["count"] > len([c for c in res["devices"] if c.get("city")])  # blank-city rows included


def test_flock_search_zip_prefix_isolates_the_county():
    box = sigint.flock_search(region="FL", bbox=PBC_BBOX)
    palm = sigint.flock_search(region="FL", bbox=PBC_BBOX, zip_prefix="334")
    assert 0 < palm["count"] < box["count"]
    assert all(str(c.get("postalcode") or "").startswith("334") for c in palm["devices"])
    broward = {"coral springs", "parkland", "pompano beach", "deerfield beach"}
    assert not {c.get("city", "").lower() for c in palm["devices"]} & broward
    assert "zip=334" in palm["detail"]


def test_flock_search_text_and_city_filters():
    text = sigint.flock_search(query="Palm Beach", region="FL")
    assert text["count"] > 0
    assert all("palm beach" in f"{c.get('city','')} {c.get('road','')}".lower() for c in text["devices"])

    cities = sigint.flock_search(region="FL", cities=["West Palm Beach"])
    assert cities["count"] > 0
    assert {c["city"].lower() for c in cities["devices"]} == {"west palm beach"}


def test_flock_search_radius_filter():
    wide = sigint.flock_search(lat=AKRON[0], lon=AKRON[1], radius_km=5.0)
    narrow = sigint.flock_search(lat=AKRON[0], lon=AKRON[1], radius_km=0.1)
    assert narrow["count"] <= wide["count"]
    assert all(c["distance_km"] <= 0.1 for c in narrow["devices"])
    assert all(c["distance_km"] is not None for c in wide["devices"])


def test_flock_search_reports_an_honest_empty_result():
    res = sigint.flock_search(region="FL", bbox=PBC_BBOX, zip_prefix="999")
    assert res["status"] == "empty"
    assert res["devices"] == []
    assert "zip=999" in res["detail"]


def test_export_cameras_csv_and_geojson(tmp_path):
    res = sigint.flock_search(region="FL", bbox=PBC_BBOX, zip_prefix="334", limit=5)
    assert res["devices"], "expected bundled Palm Beach County rows"

    csv_path = tmp_path / "nested" / "cams.csv"
    out = sigint.export_cameras(res["devices"], csv_path)
    assert out["status"] == "ok" and csv_path.exists() and out["bytes"] > 0
    lines = csv_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(res["devices"]) + 1
    assert lines[0].startswith("lat,lon,region,city,road")

    geo_path = tmp_path / "cams.geojson"
    out = sigint.export_cameras(res["devices"], geo_path)
    assert out["status"] == "ok"
    payload = json.loads(geo_path.read_text(encoding="utf-8"))
    assert payload["type"] == "FeatureCollection"
    assert len(payload["features"]) == len(res["devices"])
    first = payload["features"][0]
    source = res["devices"][0]
    assert first["geometry"]["type"] == "Point"
    # GeoJSON keeps lon/lat in the geometry only — properties carry the rest
    assert first["geometry"]["coordinates"] == [source["lon"], source["lat"]]
    assert first["properties"]["road"] == source.get("road")
    assert "lat" not in first["properties"]

    assert sigint.export_cameras([], tmp_path / "empty.csv")["status"] == "error"


def test_cli_flock_place_query_with_export(tmp_path, capsys):
    out_file = tmp_path / "palm.csv"
    rc = cli.main(["flock", "--place", "Palm Beach Florida", "--export", str(out_file)])
    printed = capsys.readouterr().out
    assert rc == 0
    assert "ALPR/Flock cameras" in printed
    if out_file.exists():
        assert "export: wrote" in printed


def test_cli_flock_bbox_and_zip(capsys):
    rc = cli.main(["flock", "--region", "FL", "--bbox", PBC_BBOX, "--zip-prefix", "334", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["count"] > 0
    assert all(str(c.get("postalcode") or "").startswith("334") for c in payload["devices"])


def test_cli_rejects_a_bad_bbox():
    with pytest.raises(ValueError):
        cli.main(["flock", "--region", "FL", "--bbox", "not,a,bbox"])


def test_chat_alpr_command_queries_local_datasets(stub_http):
    stub_http({})
    lines = iter(["alpr Palm Beach Florida", "export /tmp/wt-chat-export.csv", "quit"])
    written = []
    cli.chat(creds=EMPTY_CREDS, banner=False,
             input_fn=lambda prompt="": next(lines), output_fn=written.append)
    text = "\n".join(written)
    assert "West Palm Beach" in text or "Belvedere Road" in text
    assert "export ok" in text or "export" in text


def test_chat_alpr_requires_a_place(stub_http):
    stub_http({})
    state = {"creds": EMPTY_CREDS, "mode": "all", "radius": 1.0, "limit": 100}
    assert cli.parse_command("alpr", state)["action"] == "error"
    assert cli.parse_command("alpr Boca Raton FL", state)["action"] == "flock_query"
