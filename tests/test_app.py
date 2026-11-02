"""Regression tests for the Flask layer of WireTapper.

The network is stubbed out (both ``app.requests`` and ``sigint.requests``), so
these tests assert routing, honest "no data" answers and the endpoints the
frontend templates actually call — including the ones that used to 404.
"""

import json
import os
import sys

import pytest
import requests

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import sigint  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or ("" if payload is None else json.dumps(payload))

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


class FakeRequests:
    RequestException = requests.RequestException

    def __init__(self):
        self.calls = []

    def get(self, url, params=None, **kwargs):
        self.calls.append((url, params))
        if "nominatim" in url and "/reverse" in url:
            return FakeResponse(200, {"display_name": "Akron, Ohio, USA",
                                      "address": {"city": "Akron", "country": "United States"}})
        if "nominatim" in url:
            return FakeResponse(200, [{"lat": "41.0925", "lon": "-81.5575",
                                       "display_name": "Akron, Ohio, USA",
                                       "boundingbox": ["41.0", "41.1", "-81.6", "-81.5"]}])
        return FakeResponse(200, {"results": [], "matches": [], "features": [],
                                  "result": {"hits": []}})

    def post(self, url, params=None, **kwargs):
        self.calls.append((url, params))
        return FakeResponse(200, {"status": "ok", "cells": []})


@pytest.fixture(scope="module")
def app_module():
    import app as app_module
    return app_module


@pytest.fixture
def client(app_module, monkeypatch, tmp_path):
    """Flask test client wired to a throw-away credentials DB and activity log.

    Both paths are redirected into ``tmp_path`` so the test-suite never writes
    to the real ``credentials.db`` / ``activity.log`` in the repository.
    """
    fake = FakeRequests()
    monkeypatch.setattr(sigint, "requests", fake)
    monkeypatch.setattr(app_module, "requests", fake)
    monkeypatch.setattr(app_module, "ACTIVITY_LOG", str(tmp_path / "activity.log"))
    monkeypatch.setattr(app_module, "DB_PATH", str(tmp_path / "credentials.db"))
    app_module.init_db()          # create the table in the throw-away DB
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as test_client:
        yield test_client


def test_index_and_btscan_render(client):
    for route in ("/", "/map-w", "/btscan"):
        res = client.get(route)
        assert res.status_code == 200, route
        assert b"WireTapper" in res.data


def test_username_endpoint_exists_and_sets_cookie(client):
    res = client.get("/api/username")
    assert res.status_code == 200
    payload = res.get_json()
    assert payload["username"]
    assert "username=" in res.headers.get("Set-Cookie", "")


def test_settings_roundtrip_includes_username(client):
    get = client.get("/api/settings").get_json()
    for field in ("wigle_name", "wigle_token", "opencellid_key", "shodan_key",
                  "censys_id", "censys_secret", "username"):
        assert field in get

    post = client.post("/api/settings", json={"username": "field-analyst"})
    assert post.status_code == 200
    assert client.get("/api/settings").get_json()["username"] == "field-analyst"
    assert client.get("/api/username").get_json()["username"] == "field-analyst"


def test_log_activity_writes_jsonl(client, app_module):
    res = client.post("/log-activity", json={"username": "tester", "page": "/map-w",
                                             "event": "click", "details": "scan", "duration": "1.20"})
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"

    # sendBeacon posts text/plain, not JSON — must not 500
    beacon = client.post("/log-activity", data=json.dumps({"event": "page_leave"}),
                         content_type="text/plain")
    assert beacon.status_code == 200

    lines = open(app_module.ACTIVITY_LOG, encoding="utf-8").read().strip().splitlines()
    assert len(lines) == 2
    entry = json.loads(lines[0])
    assert entry["event"] == "click" and entry["username"] == "tester" and entry["ts"]


def test_chat_assistant_answers_with_coordinates(client):
    res = client.post("/chatgpt", json={"message": "alpr cameras near 41.0925 -81.5575 within 1km"})
    assert res.status_code == 200
    payload = res.get_json()
    assert "41.0925" in payload["reply"]
    assert "local-analyst" in payload["engine"]
    assert payload["data"]["lat"] == 41.0925


def test_chat_assistant_rejects_empty_message(client):
    assert client.post("/chatgpt", json={}).status_code == 400


def test_chat_assistant_asks_for_coordinates_when_nothing_is_found(client, monkeypatch):
    monkeypatch.setattr(sigint, "geocode",
                        lambda *a, **k: {"status": "empty", "detail": "no match"})
    res = client.post("/chatgpt", json={"message": "hello there"})
    assert res.status_code == 200
    assert "coordinates" in res.get_json()["reply"].lower()


def test_chat_assistant_survives_a_broken_geocoder(client, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("upstream exploded")

    monkeypatch.setattr(sigint, "geocode", boom)
    res = client.post("/chatgpt", json={"message": "scan around Akron"})
    assert res.status_code == 500
    assert "upstream exploded" in res.get_json()["reply"]


def test_chat_assistant_geocodes_a_place_name(client):
    res = client.post("/chatgpt", json={"message": "alpr cameras around Akron Ohio 5km"})
    assert res.status_code == 200
    payload = res.get_json()
    assert payload["data"]["lat"] == 41.0925
    assert payload["data"]["lon"] == -81.5575


def test_sdr_mode_returns_hardware_facts_not_invented_signals(client):
    res = client.get("/nearby?mode=sdr&lat=41.0925&lon=-81.5575")
    assert res.status_code == 200
    payload = res.get_json()
    assert payload["devices"] == []
    assert payload["sdr_status"]["connected"] in (True, False)
    assert "no RF" in payload["note"] or "performs no RF capture" in payload["note"]

    res = client.get("/searchzz?type=ssid&query=anything&mode=sdr")
    assert res.status_code == 200
    assert res.get_json()["devices"] == []


def test_sdr_status_endpoint(client):
    payload = client.get("/api/sdr/status").get_json()
    assert set(payload) >= {"connected", "device", "status"}


def test_iot_scan_without_keys_returns_nothing(client):
    res = client.post("/api/iot/scan", json={"lat": 47.2066, "lon": 27.795, "radius": 5})
    assert res.status_code == 200
    payload = res.get_json()
    assert payload["count"] == 0
    assert payload["devices"] == []
    assert "shodan_status" in payload and "censys_status" in payload


def test_flock_endpoints_serve_local_datasets(client):
    payload = client.get("/api/flock/datasets").get_json()
    assert payload["status"] == "success"
    datasets = payload["catalog"]
    assert datasets, "bundled ALPR datasets should be listed"

    downloaded = [d for d in datasets if d.get("is_downloaded")]
    assert downloaded
    filename = downloaded[0]["filename"]

    preview = client.get(f"/api/flock/preview?filename={filename}").get_json()
    assert preview["status"] == "success"

    cameras = client.get(f"/api/flock/cameras?filename={filename}&limit=5").get_json()
    assert cameras["status"] == "success"
    assert len(cameras["cameras"]) <= 5


def test_flock_preview_rejects_path_traversal(client):
    res = client.get("/api/flock/preview?filename=../../app.py")
    assert res.status_code in (400, 404, 500)
    assert b"def app" not in res.data


PBC = {"region": "FL", "bbox": "26.24,-80.90,27.05,-79.98", "zip": "334"}


def test_flock_query_endpoint_finds_palm_beach_county(client):
    res = client.get("/api/flock/query", query_string=PBC)
    assert res.status_code == 200
    payload = res.get_json()
    assert payload["status"] == "ok" and payload["count"] > 0
    assert all(str(c.get("postalcode") or "").startswith("334") for c in payload["devices"])
    assert all(c["type"] == "alpr_camera" for c in payload["devices"])


def test_flock_query_geojson_and_csv_formats(client):
    geo = client.get("/api/flock/query", query_string={**PBC, "format": "geojson"}).get_json()
    assert geo["type"] == "FeatureCollection" and geo["features"]

    csv_res = client.get("/api/flock/query", query_string={**PBC, "format": "csv"})
    assert csv_res.status_code == 200
    assert csv_res.mimetype == "text/csv"
    body = csv_res.get_data(as_text=True)
    assert body.splitlines()[0].startswith("lat,lon,region,city,road")
    assert len(body.strip().splitlines()) - 1 == len(geo["features"])


def test_flock_query_by_place_name(client):
    res = client.get("/api/flock/query", query_string={"q": "Palm Beach", "region": "Florida"})
    payload = res.get_json()
    assert res.status_code == 200 and payload["count"] > 0


def test_flock_query_rejects_a_bad_bbox(client):
    res = client.get("/api/flock/query", query_string={"bbox": "nope"})
    assert res.status_code == 400
    assert res.get_json()["status"] == "error"


def test_flock_query_empty_result_is_honest(client):
    payload = client.get("/api/flock/query", query_string={**PBC, "zip": "999"}).get_json()
    assert payload["status"] == "empty" and payload["devices"] == []


def test_flock_query_strict_region_flag(client):
    loose = client.get("/api/flock/query", query_string={"region": "FL"}).get_json()
    strict = client.get("/api/flock/query", query_string={"region": "FL", "strict": "1"}).get_json()
    assert loose["count"] > strict["count"] > 0
    assert strict["region_unstated"] == 0
    assert all(c["region"] == "FL" for c in strict["devices"])
