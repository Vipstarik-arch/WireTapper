"""WireTapper command-line interface.

Two ways to use WireTapper without the browser UI:

* one-shot subcommands — ``wiretaper scan --lat 47.2066 --lon 27.7950 --mode wifi``
* an interactive chat REPL — ``wiretaper chat`` and then just type coordinates::

      wt> 47.2066 27.7950 2km
      wt> wifi 47.2066 27.7950
      wt> where 47.2066 27.7950
      wt> flock 41.0925 -81.5575 3km

Everything is coordinate-driven and every answer states where its data came
from (or why a source produced nothing).  Run ``wiretaper serve`` for the
original web UI on http://0.0.0.0:8080.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys

import sigint

APP_HOST = "0.0.0.0"
APP_PORT = 8080

MODE_ALIASES = {
    "wifi": ("wifi",),
    "wi-fi": ("wifi",),
    "ap": ("wifi",),
    "bt": ("bluetooth",),
    "ble": ("bluetooth",),
    "bluetooth": ("bluetooth",),
    "cell": ("cell",),
    "cellular": ("cell",),
    "tower": ("cell",),
    "towers": ("cell",),
    "iot": ("iot",),
    "scada": ("iot",),
    "flock": ("flock",),
    "alpr": ("flock",),
    "sdr": ("sdr",),
    "all": ("wifi", "bluetooth", "cell", "iot", "flock", "sdr"),
}

STATUS_GLYPH = {"ok": "+", "empty": "-", "skipped": "!", "error": "x"}


# --------------------------------------------------------------------------- #
# Small formatting helpers
# --------------------------------------------------------------------------- #
def _cell(value, width, align="<"):
    """Pad/truncate one table cell to a fixed width (``…`` marks a cut)."""
    text = "-" if value is None or value == "" else str(value)
    if len(text) > width:
        text = text[: max(width - 1, 1)] + "\u2026"
    return format(text, f"{align}{width}")


def _fmt_distance(km):
    if km is None:
        return "-"
    if km < 1:
        return f"{km * 1000:.0f} m"
    return f"{km:.2f} km"


def render_sources(sources) -> str:
    """One line per upstream source: did it answer, and with what?"""
    lines = ["sources:"]
    for src in sources:
        glyph = STATUS_GLYPH.get(src.get("status"), "?")
        detail = src.get("detail") or ""
        if len(detail) > 150:
            detail = detail[:147] + "\u2026"
        lines.append(f"  [{glyph}] {src.get('source'):<14} {src.get('status'):<8} {src.get('count', 0):>4}  {detail}")
        if src.get("sdr_status"):
            info = src["sdr_status"]
            lines.append(f"      hardware: {info.get('device')} ({info.get('status')})")
    return "\n".join(lines)


def render_devices(devices, limit=25, wide=False) -> str:
    """Compact, chat-pasteable list of results, already sorted by distance."""
    if not devices:
        return "no devices"

    rows = devices[:limit]
    out = []

    if wide:
        header = (
            f"{_cell('#', 4)}{_cell('dist', 9, '>')}  {_cell('type', 12)}{_cell('name / road', 34)} "
            f"{_cell('id', 19)}{_cell('sig', 6, '>')}  {_cell('detail', 40)}"
        )
        out.append(header)
        out.append("-" * len(header))
        for i, d in enumerate(rows, 1):
            detail = d.get("vendor") or d.get("info") or d.get("operator") or d.get("notes") or ""
            label = d.get("ssid") or d.get("name")
            ident = d.get("bssid") or d.get("netid") or d.get("cell_id") or d.get("ip") or d.get("id")
            if d.get("encryption"):
                detail = f"{d['encryption']} · {detail}"
            if d.get("ip"):
                detail = f"{d.get('ip')}:{d.get('port')} · {detail}"
            if d.get("type") == "alpr_camera":
                label = d.get("road") or label
                zip_code = str(d.get("postalcode") or "")[:5]
                seen = str(d.get("lasttime") or "")[:10]
                detail = " · ".join(
                    part for part in (
                        d.get("city"), d.get("region"),
                        f"zip {zip_code}" if zip_code else "",
                        f"last seen {seen}" if seen else "",
                    ) if part
                )
            out.append(
                f"{_cell(i, 4)}{_cell(_fmt_distance(d.get('distance_km')), 9, '>')}  "
                f"{_cell(d.get('type'), 12)}{_cell(label, 34)} "
                f"{_cell(ident, 19)}"
                f"{_cell(d.get('signal'), 6, '>')}  {_cell(detail, 40)}"
            )
    else:
        for i, d in enumerate(rows, 1):
            ident = d.get("bssid") or d.get("netid") or d.get("cell_id") or d.get("ip") or d.get("id") or ""
            extra = d.get("encryption") or d.get("radio") or d.get("product") or d.get("operator") or ""
            label = d.get("ssid") or d.get("name")
            if d.get("type") == "alpr_camera":
                # road + municipality is what identifies a road camera
                label = d.get("road") or label
                place = " ".join(
                    p for p in (d.get("city") or "", d.get("region") or "",
                                str(d.get("postalcode") or "")[:5]) if p
                ).strip()
                extra = place or extra
            line = (
                f"{i:>3}. {_fmt_distance(d.get('distance_km')):>9}  "
                f"{_cell(d.get('type'), 12)} {_cell(label, 36)} "
                f"{_cell(ident, 20)}"
            )
            if extra:
                line += f" [{extra}]"
            out.append(line)

    if len(devices) > limit:
        out.append(f"... {len(devices) - limit} more (raise the limit)")
    return "\n".join(out)


def render_scan(result, limit=25, wide=False, show_sources=True) -> str:
    parts = [
        f"coordinates: {result['lat']}, {result['lon']}   radius: {result['radius_km']} km   "
        f"results: {result['count']}"
    ]
    if show_sources:
        parts.append(render_sources(result["sources"]))
    parts.append(render_devices(result["devices"], limit=limit, wide=wide))
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Coordinate parsing
# --------------------------------------------------------------------------- #
_RADIUS_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*(km|k|m|mi|nm|nmi)?$", re.IGNORECASE)


def parse_radius(token: str, default=1.0) -> float:
    """``2km`` / ``500m`` / ``3`` -> kilometres."""
    match = _RADIUS_RE.match(token.strip())
    if not match:
        raise ValueError(f"cannot parse radius '{token}'")
    value = float(match.group(1))
    unit = (match.group(2) or "km").lower()
    if unit in ("m",):
        return value / 1000.0
    if unit in ("mi",):
        return value * 1.609344
    if unit in ("nm", "nmi"):
        return value * 1.852
    return value


def parse_coordinates(text: str):
    """Extract ``(lat, lon, radius_token_or_None)`` from free-form chat input.

    Accepts ``47.2066 27.7950``, ``47.2066,27.7950``, ``47.2066, 27.7950 2km``,
    ``47.2066N 27.7950E`` and a lone ``2km`` radius change.
    """
    if not text:
        return None
    cleaned = text.strip().replace("\u00b0", " ").replace("'", "")
    tokens = [t for t in re.split(r"[\s,;]+", cleaned) if t]

    numbers = []
    radius_token = None
    for tok in tokens:
        signed = tok.upper().replace("N", "").replace("S", "-").replace("E", "").replace("W", "-")
        if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", signed):
            numbers.append(float(signed))
            continue
        if _RADIUS_RE.match(tok):
            radius_token = tok
            continue
        raise ValueError(f"cannot parse '{tok}' as a coordinate or radius")

    if len(numbers) >= 2:
        lat, lon = numbers[0], numbers[1]
        if not -90 <= lat <= 90 or not -180 <= lon <= 180:
            raise ValueError(f"coordinates out of range: {lat}, {lon}")
        return lat, lon, radius_token
    if radius_token and not numbers:
        return None  # radius-only change
    raise ValueError("need two numbers: latitude and longitude")


def parse_command(line: str, state: dict) -> dict:
    """Turn one chat line into an action dict (pure function — unit-testable)."""
    raw = (line or "").strip()
    if not raw:
        return {"action": "noop"}

    tokens = raw.split()
    head, rest = tokens[0].lower(), tokens[1:]
    rest_text = " ".join(rest)

    if head in ("quit", "exit", "q", ":q"):
        return {"action": "quit"}
    if head in ("help", "?", "h"):
        return {"action": "help"}
    if head in ("clear", "cls"):
        return {"action": "clear"}
    if head == "json":
        return {"action": "set_json", "value": (rest[0].lower() if rest else "toggle")}
    if head == "mode":
        return {"action": "set_mode", "value": (rest[0].lower() if rest else "")}
    if head == "radius":
        return {"action": "set_radius", "value": (rest[0] if rest else "")}
    if head == "limit":
        return {"action": "set_limit", "value": (rest[0] if rest else "")}
    if head == "last":
        return {"action": "rescan"}
    if head == "sdr":
        return {"action": "scan", "modes": ("sdr",), "coords": state.get("last_coords")}
    if head == "config":
        return {"action": "config"}
    if head == "set":
        if len(rest) < 2:
            return {"action": "error", "message": "usage: set <KEY> <VALUE>"}
        return {"action": "set_credential", "key": rest[0].upper(), "value": " ".join(rest[1:])}
    if head in ("test", "selftest", "diag"):
        return {"action": "selftest"}
    if head == "import":
        return {"action": "import", "path": rest_text}
    if head in ("datasets", "flock-list"):
        return {"action": "flock_datasets"}
    if head in ("alpr", "cameras", "roadcams"):
        if not rest_text:
            return {"action": "error", "message": "usage: alpr <place> [state] e.g. `alpr Palm Beach Florida`"}
        return {"action": "flock_query", "text": rest_text}
    if head == "export":
        if not rest_text:
            return {"action": "error", "message": "usage: export <path.csv|path.geojson>"}
        return {"action": "export", "path": rest_text}
    if head == "download":
        if not rest_text:
            return {"action": "error", "message": "usage: download <dataset id> (see flock-list)"}
        return {"action": "download", "dataset_id": rest_text}
    if head in ("ask", "q", "?q"):
        if not rest_text:
            return {"action": "error", "message": "usage: ask <question with coordinates or a place name>"}
        return {"action": "answer", "message": rest_text}
    if head in ("where", "whereami", "addr"):
        coords = _coords_from(rest_text)
        if coords is None:
            return {"action": "error", "message": "usage: where <lat> <lon>"}
        return {"action": "reverse_geocode", "lat": coords[0], "lon": coords[1]}
    if head in ("find", "geocode", "place"):
        if not rest_text:
            return {"action": "error", "message": "usage: find <place name>"}
        return {"action": "geocode", "query": rest_text}

    modes = MODE_ALIASES.get(head)
    if modes:
        coords = _coords_from(rest_text)
        if coords is None:
            return {"action": "error", "message": f"usage: {head} <lat> <lon> [radius]"}
        lat, lon, radius_token = coords
        return {
            "action": "scan",
            "modes": modes,
            "lat": lat,
            "lon": lon,
            "radius": parse_radius(radius_token) if radius_token else state.get("radius", 1.0),
            "coords": (lat, lon),
        }

    # Bare coordinates: "47.2066 27.7950 2km"
    try:
        coords = _coords_from(raw)
    except ValueError as exc:
        return {"action": "error", "message": str(exc)}
    if coords is None:
        if _RADIUS_RE.match(raw):
            return {"action": "set_radius", "value": raw}
        # Free-form question -> the local analyst reads coordinates/radius/source
        # out of it ("что рядом с 47.2066 27.7950 в радиусе 2 км", "wifi near Akron").
        return {"action": "answer", "message": raw}
    lat, lon, radius_token = coords
    default_modes = MODE_ALIASES.get(state.get("mode", "all"), MODE_ALIASES["all"])
    return {
        "action": "scan",
        "modes": default_modes,
        "lat": lat,
        "lon": lon,
        "radius": parse_radius(radius_token) if radius_token else state.get("radius", 1.0),
        "coords": (lat, lon),
    }


def _coords_from(text: str):
    """Best-effort coordinate extraction; returns ``None`` when there is nothing."""
    if not text or not text.strip():
        return None
    try:
        return parse_coordinates(text)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
def execute(command: dict, state: dict, creds=None) -> str:
    """Run a parsed chat command and return printable text."""
    creds = creds or state.get("creds") or sigint.Credentials()
    state["creds"] = creds
    action = command.get("action")

    if action == "noop":
        return ""
    if action == "error":
        return f"! {command['message']}"
    if action == "help":
        return HELP_TEXT
    if action == "clear":
        return "\x1bc"
    if action == "quit":
        state["quit"] = True
        return "bye"

    if action == "set_json":
        value = command.get("value", "toggle")
        state["json"] = not state.get("json") if value == "toggle" else value in ("on", "1", "true", "yes")
        return f"json output: {'on' if state['json'] else 'off'}"

    if action == "set_mode":
        value = command.get("value", "")
        if value not in MODE_ALIASES:
            return f"! unknown mode {value!r} — choose from: {', '.join(sorted(MODE_ALIASES))}"
        state["mode"] = "all" if value == "all" else MODE_ALIASES[value][0]
        return f"default mode for bare coordinates: {state['mode']}"

    if action == "set_radius":
        try:
            state["radius"] = parse_radius(command.get("value", ""))
        except ValueError:
            return "! usage: radius <value> e.g. `radius 2km` or `radius 500m`"
        return f"default radius: {_fmt_distance(state['radius'])}"

    if action == "set_limit":
        try:
            state["limit"] = max(1, int(command.get("value", "")))
        except ValueError:
            return "! usage: limit <number>"
        return f"result limit: {state['limit']}"

    if action == "config":
        rows = creds.report()
        out = ["credentials (values are never printed in full):"]
        for row in rows:
            mark = "set " if row["configured"] else "MISS"
            out.append(f"  [{mark}] {row['key']:<20} {row['masked']:<24} from {row['origin']}")
        out.append("")
        out.append("edit them here (`set KEY VALUE`) or in the web UI (/api/settings).")
        return "\n".join(out)

    if action == "set_credential":
        save_credential(command["key"], command["value"])
        state["creds"] = sigint.Credentials()
        return f"saved {command['key']} = {sigint.Credentials.mask(command['value'])} -> credentials.db"

    if action == "selftest":
        report = sigint.self_test(creds)
        if state.get("json"):
            return sigint.to_json(report)
        out = ["connectivity / capability self-test:"]
        for check in report["checks"]:
            reachable = check.get("reachable")
            glyph = "+" if reachable else ("!" if reachable is None else "x")
            out.append(f"  [{glyph}] {_cell(check['name'], 28)} {check['detail']}")
        return "\n".join(out)

    if action == "geocode":
        res = sigint.geocode(command["query"])
        if state.get("json"):
            return sigint.to_json(res)
        if res["status"] != "ok":
            return f"! geocode {res['status']}: {res['detail']}"
        state["last_coords"] = (res["lat"], res["lon"])
        return (
            f"{res['display_name']}\n  lat={res['lat']}  lon={res['lon']}\n"
            f"  (saved as `last` — press Enter-less `last` to re-scan these coordinates)"
        )

    if action == "reverse_geocode":
        lat, lon = command["lat"], command["lon"]
        state["last_coords"] = (lat, lon)
        res = sigint.reverse_geocode(lat, lon)
        if state.get("json"):
            return sigint.to_json(res)
        if res["status"] != "ok":
            return f"! reverse geocode {res['status']}: {res['detail']}"
        address = res.get("address") or {}
        line = f"{lat}, {lon} -> {res['display_name']}"
        if address:
            bits = [address.get(k) for k in ("city", "town", "village", "county", "state", "country")]
            line += "\n  " + " / ".join(b for b in bits if b)
        return line

    if action == "answer":
        res = sigint.answer(command.get("message", ""), creds=creds)
        if state.get("json"):
            return sigint.to_json(res)
        reply = res.get("reply", "")
        coords = sigint.extract_coordinates(command.get("message", ""))
        if coords:
            state["last_coords"] = coords
        return reply

    if action == "flock_query":
        text = command.get("text", "")
        query, region = sigint.split_place_state(text)
        res = sigint.flock_search(query=query or None, region=region or None)
        state["last_export"] = res["devices"]
        if state.get("json"):
            return sigint.to_json(res)
        header = f"ALPR/Flock cameras matching {text!r} — {res['count']} found"
        return "\n".join([header, res["detail"],
                          render_devices(res["devices"], limit=state.get("limit_display", 25),
                                         wide=state.get("wide", False))])

    if action == "export":
        rows = state.get("last_export")
        if not rows:
            return "! nothing to export yet — run a scan or an `alpr <place>` query first"
        out = sigint.export_cameras(rows, command["path"])
        return f"export {out['status']}: {out['detail']} -> {out.get('path')}" if out["status"] == "ok" \
            else f"! export failed: {out['detail']}"

    if action == "download":
        res = sigint.flock_download(command["dataset_id"])
        if state.get("json"):
            return sigint.to_json(res)
        return f"download {res.get('status')}: {res.get('message')}"

    if action == "flock_datasets":
        res = sigint.flock_datasets()
        if state.get("json"):
            return sigint.to_json(res)
        out = ["local Flock / ALPR datasets:"]
        for ds in res["datasets"]:
            mark = "local" if ds.get("is_downloaded") else "not downloaded"
            count = ds.get("camera_count")
            out.append(
                f"  [{mark:<14}] {_cell(ds['name'], 44)} {str(count or '-') + ' records':>14}  {ds['filename']}"
            )
        return "\n".join(out)

    if action == "import":
        path = command.get("path") or ""
        if not path:
            return "! usage: import <path-to-csv/kml/geojson/db/xlsx>"
        res = sigint.import_telemetry(os.path.expanduser(path))
        if state.get("json"):
            return sigint.to_json(res)
        if res.get("status") != "success":
            return f"! import {res.get('status')}: {res.get('message')}"
        out = [
            f"{res['filename']}  {res['format']}  {res['file_size']} bytes  {res['total_rows']} rows",
            f"  columns: {', '.join(res['columns'][:14])}",
            f"  detected mapping: {json.dumps(res['detected_mappings'], ensure_ascii=False)}",
        ]
        return "\n".join(out)

    if action == "rescan":
        coords = state.get("last_coords")
        if not coords:
            return "! no previous coordinates — send `<lat> <lon>` first"
        command = {
            "action": "scan",
            "modes": MODE_ALIASES.get(state.get("mode", "all"), MODE_ALIASES["all"]),
            "lat": coords[0],
            "lon": coords[1],
            "radius": state.get("radius", 1.0),
        }
        action = "scan"

    if action == "scan":
        coords = command.get("coords") or state.get("last_coords")
        if coords and "lat" not in command:
            command = dict(command, lat=coords[0], lon=coords[1], radius=state.get("radius", 1.0))
        if "lat" not in command or command.get("lat") is None:
            return "! no coordinates — send `<lat> <lon> [radius]`"
        lat, lon = float(command["lat"]), float(command["lon"])
        radius = float(command.get("radius") or state.get("radius", 1.0))
        state["last_coords"] = (lat, lon)
        state["last_radius"] = radius
        modes = tuple(command.get("modes") or ("wifi",))
        result = sigint.scan(lat, lon, radius_km=radius, modes=modes, creds=creds,
                             limit=state.get("limit", 100))
        state["last_export"] = result["devices"]
        if state.get("json"):
            return sigint.to_json(result)
        return render_scan(result, limit=state.get("limit_display", 25), wide=state.get("wide", False))

    return f"! unhandled action: {action}"


HELP_TEXT = """WireTapper chat mode — everything is driven by coordinates.

  <lat> <lon> [radius]     scan with the default mode (currently: all sources)
  wifi|bt|cell|iot|flock|sdr|all <lat> <lon> [radius]
                           scan one source, e.g. `wifi 47.2066 27.7950 2km`
  where <lat> <lon>        reverse-geocode: what place is this?
  find <place name>        geocode a place, then reuse it with `last`
  last                     re-scan the previous coordinates
  ask <free text>          natural-language query, e.g. `ask wifi near 47.2066 27.7950 2km`
                           (any line that is not a command is treated the same way)
  alpr <place> [state]     road/ALPR cameras for a place, e.g. `alpr Palm Beach Florida`
  export <file.csv|.geojson>  write the last result set to a file
  flock-list               which ALPR datasets are available locally
  download <dataset id>    fetch a catalog dataset (needs internet egress)
  import <file>            inspect a CSV/KML/GeoJSON/SQLite/Excel telemetry file
  sdr                      report the attached USB SDR receiver (hardware facts only)

  mode <name>              default mode for bare coordinates
  radius <2km|500m>        default radius
  limit <n>                max results kept per scan
  json on|off              raw JSON instead of tables (handy for pasting)
  config                   which API keys are configured (masked)
  set <KEY> <VALUE>        save an API key to credentials.db
  test                     connectivity + capability self-test
  help · clear · quit

Sources: WiGLE (Wi-Fi/Bluetooth/cell), OpenCellID, Shodan, Censys,
OpenStreetMap Nominatim, local Flock/ALPR datasets, local USB SDR probe.
A source with no key or no network is reported as skipped/error — never faked."""


def save_credential(key: str, value: str, db_path: str = sigint.DB_PATH) -> bool:
    """Persist one API key into the same SQLite table the web UI uses."""
    if key not in sigint.Credentials.KEYS:
        raise KeyError(f"{key} is not a WireTapper credential ({', '.join(sigint.Credentials.KEYS)})")
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS credentials ("
                "key TEXT PRIMARY KEY, value TEXT, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            )
            conn.execute(
                "INSERT INTO credentials (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
                (key, value),
            )
            conn.commit()
        return True
    except sqlite3.Error as exc:
        print(f"could not write {db_path}: {exc}", file=sys.stderr)
        return False


# --------------------------------------------------------------------------- #
# Chat REPL
# --------------------------------------------------------------------------- #
def chat(creds=None, banner=True, input_fn=None, output_fn=None, initial_state=None):
    """Interactive coordinate-driven REPL (``wiretaper chat``)."""
    creds = creds or sigint.Credentials()
    state = {
        "creds": creds,
        "mode": "all",
        "radius": 1.0,
        "limit": 100,
        "limit_display": 25,
        "json": False,
        "wide": False,
        "quit": False,
    }
    state.update(initial_state or {})
    read = input_fn or input
    write = output_fn or (lambda text: print(text))

    if banner:
        write("WireTapper chat mode. Type 'help' for commands, 'quit' to leave.")
        mode_label = "all sources" if state["mode"] == "all" else state["mode"]
        write(f"Default scan: {mode_label}, radius {_fmt_distance(state['radius'])}.")
        missing = [r["key"] for r in creds.report() if not r["configured"]]
        if missing:
            write(f"Note: not configured -> {', '.join(missing)} (those sources will be skipped).")
        write("")

    while not state.get("quit"):
        try:
            line = read("wt> ")
        except (EOFError, KeyboardInterrupt):
            write("\nbye")
            break
        command = parse_command(line, state)
        if command.get("action") == "quit":
            write("bye")
            break
        try:
            output = execute(command, state, creds)
        except Exception as exc:  # keep the REPL alive on any single failure
            output = f"! {type(exc).__name__}: {exc}"
        if output:
            write(output)
    return state


# --------------------------------------------------------------------------- #
# argparse subcommands
# --------------------------------------------------------------------------- #
def _add_common(parser):
    parser.add_argument("--lat", type=float, help="latitude (decimal degrees)")
    parser.add_argument("--lon", type=float, help="longitude (decimal degrees)")
    parser.add_argument("--radius", default="1km", help="search radius, e.g. 500m, 2km, 3mi (default 1km)")
    parser.add_argument("--limit", type=int, default=100, help="max results (default 100)")
    parser.add_argument("--json", action="store_true", help="print raw JSON instead of a table")
    parser.add_argument("--wide", action="store_true", help="wider table with vendor/detail columns")
    parser.add_argument("--timeout", type=int, default=sigint.DEFAULT_TIMEOUT, help="per-request timeout in seconds")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wiretaper",
        description="WireTapper — coordinate-driven wireless OSINT / signal intelligence.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  wiretaper chat\n"
            "  wiretaper scan --lat 47.2066 --lon 27.7950 --radius 2km --mode all\n"
            "  wiretaper flock --lat 41.0925 --lon -81.5575 --radius 3km\n"
            "  wiretaper where --lat 47.2066 --lon 27.7950\n"
            "  wiretaper selftest\n"
            "  wiretaper serve          # original web UI on :8080\n"
        ),
    )
    sub = parser.add_subparsers(dest="command")

    p_chat = sub.add_parser("chat", help="interactive coordinate-driven REPL")
    p_chat.add_argument("--mode", default="all", choices=sorted(MODE_ALIASES), help="default scan mode")
    p_chat.add_argument("--radius", default="1km", help="default radius")
    p_chat.add_argument("--json", action="store_true", help="start with JSON output on")

    p_scan = sub.add_parser("scan", help="scan coordinates across one or more sources")
    _add_common(p_scan)
    p_scan.add_argument("--mode", default="all", help="wifi, bluetooth, cell, iot, flock, sdr, all (comma-separated)")
    p_scan.add_argument("--no-shodan", action="store_true", help="skip Shodan in iot mode")
    p_scan.add_argument("--no-censys", action="store_true", help="skip Censys in iot mode")

    p_flock = sub.add_parser("flock", help="ALPR / Flock Safety cameras near coordinates (offline datasets)")
    _add_common(p_flock)
    p_flock.add_argument("--dataset", action="append", help="restrict to dataset filename(s) or id(s)")
    p_flock.add_argument("--place", help='place + state, e.g. "Palm Beach Florida"')
    p_flock.add_argument("--query", help="free-text filter over city/road/SSID/name/notes")
    p_flock.add_argument("--region", help="US state (FL or Florida)")
    p_flock.add_argument("--city", action="append", help="restrict to city name(s), repeatable")
    p_flock.add_argument("--bbox", help="bounding box: south,west,north,east")
    p_flock.add_argument("--zip-prefix", help='postal-code prefix filter, e.g. "334" for Palm Beach County')
    p_flock.add_argument("--strict-region", action="store_true",
                         help="drop rows from datasets that record no state at all")
    p_flock.add_argument("--export", metavar="PATH", help="write results to .csv or .geojson")
    p_flock.set_defaults(radius="10km")  # ALPR data is sparse; 1 km rarely matches

    p_dl = sub.add_parser("flock-download", help="download a catalog ALPR dataset (needs egress)")
    p_dl.add_argument("dataset_id")
    p_dl.add_argument("--json", action="store_true")

    p_where = sub.add_parser("where", help="reverse-geocode coordinates into a place name")
    p_where.add_argument("--lat", type=float, required=True)
    p_where.add_argument("--lon", type=float, required=True)
    p_where.add_argument("--json", action="store_true")

    p_find = sub.add_parser("find", help="geocode a place name into coordinates")
    p_find.add_argument("query", nargs="+")
    p_find.add_argument("--json", action="store_true")

    p_sdr = sub.add_parser("sdr", help="report attached USB SDR hardware")
    p_sdr.add_argument("--json", action="store_true")

    p_import = sub.add_parser("import", help="inspect/process a telemetry file (CSV/KML/GeoJSON/SQLite/Excel)")
    p_import.add_argument("path")
    p_import.add_argument("--json", action="store_true")
    p_import.add_argument("--map", action="append", default=[], metavar="FIELD=COLUMN",
                          help="column mapping, e.g. --map lat=trilat --map lon=trilong")

    p_ds = sub.add_parser("datasets", help="list local Flock/ALPR datasets")
    p_ds.add_argument("--json", action="store_true")

    p_cfg = sub.add_parser("config", help="show or set API credentials")
    p_cfg.add_argument("pairs", nargs="*", metavar="KEY=VALUE", help="set one or more credentials")
    p_cfg.add_argument("--json", action="store_true")

    p_test = sub.add_parser("selftest", help="check keys, upstream reachability and local data")
    p_test.add_argument("--json", action="store_true")

    p_serve = sub.add_parser("serve", help="run the Flask web UI (default action)")
    p_serve.add_argument("--host", default=APP_HOST)
    p_serve.add_argument("--port", type=int, default=APP_PORT)
    p_serve.add_argument("--debug", action="store_true")

    return parser


def _modes_from(text: str):
    modes = []
    for part in str(text).replace("+", ",").split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part not in MODE_ALIASES:
            raise SystemExit(f"unknown mode '{part}' — choose from: {', '.join(sorted(MODE_ALIASES))}")
        modes.extend(MODE_ALIASES[part])
    return tuple(dict.fromkeys(modes))


LEGACY_START = ("-start", "--start", "start", "run", "web")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Backwards compatibility with the original launcher: bare `wiretaper`,
    # `wiretaper start`, `wiretaper run`, `wiretaper -start` all serve the web UI.
    if not argv or argv[0] in LEGACY_START:
        return cmd_serve(build_parser().parse_args(["serve"]))

    parser = build_parser()
    args = parser.parse_args(argv)
    handler = {
        "chat": cmd_chat,
        "scan": cmd_scan,
        "flock": cmd_flock,
        "flock-download": cmd_flock_download,
        "where": cmd_where,
        "find": cmd_find,
        "sdr": cmd_sdr,
        "import": cmd_import,
        "datasets": cmd_datasets,
        "config": cmd_config,
        "selftest": cmd_selftest,
        "serve": cmd_serve,
    }[args.command]
    return handler(args)


# -- handlers --------------------------------------------------------------- #
def cmd_serve(args) -> int:
    host = getattr(args, "host", APP_HOST)
    port = getattr(args, "port", APP_PORT)
    debug = getattr(args, "debug", False)
    print(f"Starting WireTapper Signal Intelligence Platform on http://{host}:{port} ...")
    from app import app  # imported late so CLI-only use does not need Flask

    app.run(host=host, port=port, debug=debug)
    return 0


def _coords_or_die(args):
    if args.lat is None or args.lon is None:
        raise SystemExit("both --lat and --lon are required (or use `wiretaper chat`)")
    if not -90 <= args.lat <= 90 or not -180 <= args.lon <= 180:
        raise SystemExit(f"coordinates out of range: {args.lat}, {args.lon}")
    return args.lat, args.lon


def cmd_chat(args) -> int:
    try:
        radius = parse_radius(args.radius)
    except ValueError:
        raise SystemExit(f"cannot parse --radius '{args.radius}' (try 500m, 2km, 3mi)")
    modes = MODE_ALIASES.get(args.mode, MODE_ALIASES["all"])
    chat(
        creds=sigint.Credentials(),
        initial_state={
            "mode": "all" if args.mode == "all" else modes[0],
            "radius": radius,
            "json": bool(args.json),
        },
    )
    return 0


def cmd_scan(args) -> int:
    lat, lon = _coords_or_die(args)
    radius = parse_radius(args.radius)
    modes = _modes_from(args.mode)
    result = sigint.scan(
        lat,
        lon,
        radius_km=radius,
        modes=modes,
        creds=sigint.Credentials(),
        limit=args.limit,
        timeout=args.timeout,
        use_shodan=not args.no_shodan,
        use_censys=not args.no_censys,
    )
    if args.json:
        print(sigint.to_json(result))
    else:
        print(render_scan(result, limit=args.limit, wide=args.wide))
    return 0


def cmd_flock(args) -> int:
    query_mode = any([args.query, args.region, args.bbox, args.city, args.place, args.zip_prefix])
    lat = lon = None
    if args.lat is not None or args.lon is not None:
        lat, lon = _coords_or_die(args)

    region, cities = args.region, list(args.city or [])
    query = args.query or ""
    if args.place:
        query, place_region = sigint.split_place_state(args.place)
        region = region or place_region

    if query_mode:
        res = sigint.flock_search(query=query or None, region=region, bbox=args.bbox,
                                 cities=cities, zip_prefix=args.zip_prefix, lat=lat, lon=lon,
                                 radius_km=parse_radius(args.radius) if lat is not None else None,
                                 datasets=args.dataset, limit=args.limit,
                                 strict_region=args.strict_region)
    elif lat is not None:
        res = sigint.flock_near(lat, lon, radius_km=parse_radius(args.radius),
                                datasets=args.dataset, limit=args.limit)
    else:
        raise SystemExit(
            "give either coordinates (--lat/--lon) or a query "
            "(--place \"Palm Beach Florida\", --query/--region/--bbox/--city)"
        )

    if args.json:
        print(sigint.to_json(res))
    else:
        print(f"ALPR/Flock cameras — {res['count']} found")
        print(res["detail"])
        print(render_devices(res["devices"], limit=args.limit, wide=args.wide))
    if args.export and res["devices"]:
        out = sigint.export_cameras(res["devices"], args.export)
        print(f"export: {out['detail']} -> {out['path']} ({out.get('bytes', 0)} bytes)")
    return 0


def cmd_flock_download(args) -> int:
    res = sigint.flock_download(args.dataset_id)
    if args.json:
        print(sigint.to_json(res))
    else:
        print(f"{res.get('status')}: {res.get('message')}")
        if res.get("camera_count") is not None:
            print(f"  cameras parsed: {res['camera_count']} of {res.get('total_records')} records")
    return 0 if res.get("status") == "success" else 1


def cmd_where(args) -> int:
    res = sigint.reverse_geocode(args.lat, args.lon)
    print(sigint.to_json(res) if args.json else (res.get("display_name") or f"{res['status']}: {res['detail']}"))
    return 0


def cmd_find(args) -> int:
    query = " ".join(args.query)
    res = sigint.geocode(query)
    if args.json:
        print(sigint.to_json(res))
    elif res["status"] == "ok":
        print(f"{res['display_name']}\n  lat={res['lat']}  lon={res['lon']}")
    else:
        print(f"{res['status']}: {res['detail']}")
    return 0


def cmd_sdr(args) -> int:
    info = sigint.detect_sdr()
    if args.json:
        print(sigint.to_json(info))
    else:
        print(f"{info['status']}: {info['device']}")
        print(f"  {info['detail']}")
        if info.get("frequency_range"):
            print(f"  tuning range: {info['frequency_range']}")
    return 0


def cmd_import(args) -> int:
    path = os.path.expanduser(args.path)
    mappings = None
    if args.map:
        mappings = {}
        for pair in args.map:
            if "=" not in pair:
                raise SystemExit(f"--map expects FIELD=COLUMN, got '{pair}'")
            field, column = pair.split("=", 1)
            mappings[field.strip().lower()] = column.strip()
    res = sigint.import_telemetry(path, mappings)
    if args.json:
        print(sigint.to_json(res))
        return 0
    if res.get("status") != "success":
        print(f"{res.get('status')}: {res.get('message')}")
        return 1
    if mappings is None:
        print(f"{res['filename']}  {res['format']}  {res['file_size']} bytes  {res['total_rows']} rows")
        print(f"  columns: {', '.join(res['columns'])}")
        print(f"  detected mapping: {json.dumps(res['detected_mappings'], ensure_ascii=False)}")
        print("  re-run with --map lat=COL --map lon=COL ... to normalise it")
    else:
        print(f"normalised {res.get('count', len(res.get('devices', [])))} devices")
        print(render_devices(res.get("devices", []), limit=25))
    return 0


def cmd_datasets(args) -> int:
    res = sigint.flock_datasets()
    if args.json:
        print(sigint.to_json(res))
        return 0
    for ds in res["datasets"]:
        mark = "local" if ds.get("is_downloaded") else "not downloaded"
        print(f"[{mark:<14}] {ds['name']} — {ds.get('camera_count') or '-'} records ({ds['filename']})")
    return 0


def cmd_config(args) -> int:
    creds = sigint.Credentials()
    for pair in args.pairs or []:
        if "=" not in pair:
            raise SystemExit(f"expected KEY=VALUE, got '{pair}'")
        key, value = pair.split("=", 1)
        try:
            save_credential(key.strip().upper(), value.strip())
        except KeyError as exc:
            raise SystemExit(str(exc))
        print(f"saved {key.strip().upper()}")
        creds = sigint.Credentials()
    rows = creds.report()
    if args.json:
        print(sigint.to_json({"credentials": rows}))
        return 0
    for row in rows:
        mark = "set " if row["configured"] else "MISS"
        print(f"[{mark}] {row['key']:<20} {row['masked']:<24} from {row['origin']}")
    return 0


def cmd_selftest(args) -> int:
    res = sigint.self_test(sigint.Credentials())
    if args.json:
        print(sigint.to_json(res))
        return 0
    print("credentials:")
    for row in res["credentials"]:
        mark = "set " if row["configured"] else "MISS"
        print(f"  [{mark}] {row['key']:<20} {row['masked']:<24} from {row['origin']}")
    print("\nchecks:")
    for check in res["checks"]:
        reachable = check.get("reachable")
        glyph = "+" if reachable else ("!" if reachable is None else "x")
        print(f"  [{glyph}] {check['name']:<30} {check['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
