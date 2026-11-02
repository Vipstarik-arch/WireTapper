import requests
import ssl
import json
import os
import getpass
import sqlite3
import time
import threading
import subprocess
import platform
import asyncio
from datetime import datetime, timezone
from collections import deque
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, render_template
import telemetry_importer
import flock_manager
import sigint

app = Flask(__name__)

# Telemetry Uploads Storage
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

## SQLite Database Credentials Storage
DB_PATH = os.path.join(os.path.dirname(__file__), 'credentials.db')

def init_db():
    """Initializes the credentials table in SQLite and seeds from .env if empty."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()

            # Seed defaults
            env_file = os.path.join(os.path.dirname(__file__), '.env')
            defaults = {
                'WIGLE_API_NAME': 'your_wigle_api_name',
                'WIGLE_API_TOKEN': 'your_wigle_api_token',
                'OPENCELLID_API_KEY': 'your_opencellid_api_key',
                'SHODAN_API_KEY': 'your_shodan_api_key',
                'CENSYS_API_ID': 'your_censys_api_id',
                'CENSYS_API_SECRET': 'your_censys_api_secret'
            }
            if os.path.exists(env_file):
                try:
                    with open(env_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#') and '=' in line:
                                k, v = line.split('=', 1)
                                defaults[k.strip()] = v.strip()
                except Exception as e:
                    print("Initial .env read error:", e)

            for k, v in defaults.items():
                cursor.execute('INSERT OR IGNORE INTO credentials (key, value) VALUES (?, ?)', (k, v))
            conn.commit()
    except Exception as e:
        print("Database initialization error:", e)

def get_db_credential(key, default=''):
    """Reads a credential value from SQLite."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM credentials WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row and row[0] is not None:
                return row[0]
    except Exception as e:
        print(f"Error fetching credential {key} from database:", e)
    return default

def set_db_credentials(creds_dict):
    """Saves multiple credentials into SQLite."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            for k, v in creds_dict.items():
                cursor.execute('''
                    INSERT INTO credentials (key, value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = CURRENT_TIMESTAMP
                ''', (k, v))
            conn.commit()
            return True
    except Exception as e:
        print("Error saving credentials to database:", e)
        return False

# Initialize the database and load credentials into runtime memory
init_db()
WIGLE_API_NAME = get_db_credential("WIGLE_API_NAME", "your_wigle_api_name")
WIGLE_API_TOKEN = get_db_credential("WIGLE_API_TOKEN", "your_wigle_api_token")
OPENCELLID_API_KEY = get_db_credential("OPENCELLID_API_KEY", "your_opencellid_api_key")
SHODAN_API_KEY = get_db_credential("SHODAN_API_KEY", "your_shodan_api_key")
CENSYS_API_ID = get_db_credential("CENSYS_API_ID", "your_censys_api_id")
CENSYS_API_SECRET = get_db_credential("CENSYS_API_SECRET", "your_censys_api_secret")

# Real intercept store (no fake/dummy fallback data)
DUMMY_DATA = []

@app.route('/')
@app.route('/map-w')
def wifi_map():
    return render_template('wifi-search.html')

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    global WIGLE_API_NAME, WIGLE_API_TOKEN, OPENCELLID_API_KEY, SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET
    if request.method == 'POST':
        data = request.get_json() or {}
        updates = {}
        if 'wigle_name' in data:
            WIGLE_API_NAME = data['wigle_name'].strip()
            updates['WIGLE_API_NAME'] = WIGLE_API_NAME
        if 'wigle_token' in data:
            WIGLE_API_TOKEN = data['wigle_token'].strip()
            updates['WIGLE_API_TOKEN'] = WIGLE_API_TOKEN
        if 'opencellid_key' in data:
            OPENCELLID_API_KEY = data['opencellid_key'].strip()
            updates['OPENCELLID_API_KEY'] = OPENCELLID_API_KEY
        if 'shodan_key' in data:
            SHODAN_API_KEY = data['shodan_key'].strip()
            updates['SHODAN_API_KEY'] = SHODAN_API_KEY
        if 'censys_id' in data:
            CENSYS_API_ID = data['censys_id'].strip()
            updates['CENSYS_API_ID'] = CENSYS_API_ID
        if 'censys_secret' in data:
            CENSYS_API_SECRET = data['censys_secret'].strip()
            updates['CENSYS_API_SECRET'] = CENSYS_API_SECRET
        if 'username' in data:
            updates['USERNAME'] = str(data['username']).strip()[:64]
        
        # Save to SQLite credentials.db
        saved = set_db_credentials(updates)

        if saved:
            return jsonify({
                'status': 'success',
                'message': 'Credentials saved to SQLite database (credentials.db)'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Database write failed'
            }), 500
    else:
        return jsonify({
            'wigle_name': get_db_credential('WIGLE_API_NAME', WIGLE_API_NAME),
            'wigle_token': get_db_credential('WIGLE_API_TOKEN', WIGLE_API_TOKEN),
            'opencellid_key': get_db_credential('OPENCELLID_API_KEY', OPENCELLID_API_KEY),
            'shodan_key': get_db_credential('SHODAN_API_KEY', SHODAN_API_KEY),
            'censys_id': get_db_credential('CENSYS_API_ID', CENSYS_API_ID),
            'censys_secret': get_db_credential('CENSYS_API_SECRET', CENSYS_API_SECRET),
            'username': get_db_credential('USERNAME', '')
        })

# --------------------------------------------------------------------------- #
# Operator identity, activity log and the in-app chat assistant
# --------------------------------------------------------------------------- #
ACTIVITY_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'activity.log')


@app.route('/api/username')
def api_username():
    """Operator name shown in the UI header (also seeds the `username` cookie)."""
    name = (
        get_db_credential('USERNAME', '').strip()
        or os.environ.get('WIRETAPPER_USER', '').strip()
        or request.cookies.get('username', '').strip()
    )
    if not name:
        try:
            name = getpass.getuser()
        except Exception:
            name = 'anonymous'
    response = jsonify({
        'username': name,
        'source': 'local operator account',
        'note': 'Rename with POST /api/settings {"username": "..."}'
    })
    response.set_cookie('username', name, max_age=60 * 60 * 24 * 365, samesite='Lax')
    return response


@app.route('/log-activity', methods=['POST'])
def log_activity():
    """Append a UI event to the local activity log (JSON lines, git-ignored)."""
    payload = request.get_json(silent=True)
    if payload is None:
        # navigator.sendBeacon posts text/plain
        try:
            payload = json.loads(request.get_data(as_text=True) or '{}')
        except ValueError:
            payload = {}
    if not isinstance(payload, dict):
        payload = {}

    entry = {
        'ts': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'username': payload.get('username') or request.cookies.get('username') or 'anonymous',
        'page': payload.get('page') or request.referrer or '',
        'event': payload.get('event') or 'unknown',
        'details': str(payload.get('details', ''))[:300],
        'duration': payload.get('duration'),
        'ip': request.remote_addr,
    }
    try:
        with open(ACTIVITY_LOG, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except OSError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 500
    return jsonify({'status': 'ok'})


@app.route('/chatgpt', methods=['POST'])
def chat_assistant():
    """Coordinate-driven assistant behind the in-app chat panel.

    A deterministic local analyst: it reads coordinates / a radius / the wanted
    sources out of the message, queries the configured sources through
    `sigint.scan()` and reports exactly what came back — including the sources
    that stayed silent and why. No external LLM is called, so nothing is
    invented when a key is missing.
    """
    data = request.get_json(silent=True) or {}
    message = str(data.get('message') or data.get('prompt') or '').strip()
    if not message:
        return jsonify({'reply': 'Send coordinates, e.g. `47.2066 27.7950 2km`, or a place name.'}), 400

    try:
        result = sigint.answer(message, timeout=10)
    except Exception as exc:
        return jsonify({'reply': f'Analyst error: {type(exc).__name__}: {exc}'}), 500

    return jsonify({
        'reply': result['reply'],
        'engine': 'wiretapper-local-analyst (rule-based, no external LLM)',
        'web_search': bool(data.get('web_search')),
        'data': result.get('data', {}),
    })


def check_usb_sdr_status():
    """Checks if a physical USB SDR receiver (e.g. RTL-SDR, HackRF, Airspy) is attached via USB."""
    connected = False
    device_name = "SDR USB Dongle"
    freq_range = "24 MHz - 1766 MHz"

    usb_dir = "/sys/bus/usb/devices"
    if os.path.exists(usb_dir):
        try:
            for dev in os.listdir(usb_dir):
                vp_path = os.path.join(usb_dir, dev)
                id_vendor = os.path.join(vp_path, "idVendor")
                id_product = os.path.join(vp_path, "idProduct")
                product_file = os.path.join(vp_path, "product")

                vendor_id = ""
                product_id = ""
                product_str = ""

                if os.path.exists(id_vendor):
                    with open(id_vendor, 'r') as f:
                        vendor_id = f.read().strip().lower()
                if os.path.exists(id_product):
                    with open(id_product, 'r') as f:
                        product_id = f.read().strip().lower()
                if os.path.exists(product_file):
                    with open(product_file, 'r', errors='ignore') as f:
                        product_str = f.read().strip()

                if (vendor_id == '0bda' and product_id in ['2838', '2832']) or 'rtl' in product_str.lower():
                    connected = True
                    device_name = product_str or "RTL2838UHIDIR RTL-SDR Blog V4"
                    freq_range = "500 kHz - 1766 MHz"
                    break
                elif (vendor_id == '1d50' and product_id in ['6089', '604b']) or 'hackrf' in product_str.lower():
                    connected = True
                    device_name = product_str or "Great Scott Gadgets HackRF One"
                    freq_range = "1 MHz - 6 GHz"
                    break
                elif (vendor_id == '1d50' and product_id == '60a1') or 'airspy' in product_str.lower():
                    connected = True
                    device_name = product_str or "Airspy R2 / Mini"
                    freq_range = "24 MHz - 1800 MHz"
                    break
                elif 'sdr' in product_str.lower() or 'software defined radio' in product_str.lower():
                    connected = True
                    device_name = product_str
                    break
        except Exception as e:
            print(f"USB scan exception: {e}")

    return {
        "connected": connected,
        "device": device_name if connected else "No SDR Device Detected",
        "frequency_range": freq_range,
        "status": "Active Hardware Link" if connected else "Disconnected"
    }

@app.route('/api/sdr/status')
def sdr_status():
    return jsonify(check_usb_sdr_status())

def classify_device(name, original_type):
    if not name:
        return original_type
    name_upper = name.upper()
    if any(k in name_upper for k in ["SDR", "RTL-SDR", "HACKRF", "ADSB", "SUBGHZ", "RF_BEACON", "HAM_RADIO", "RADIO", "433MHZ", "868MHZ", "915MHZ"]):
        return "sdr"
    if any(k in name_upper for k in ["CAR", "FORD", "TOYOTA", "BMW", "TESLA", "SYNC", "MAZDA", "HONDA", "UCONNECT", "HYUNDAI", "LEXUS", "NISSAN"]):
        return "car"
    if any(k in name_upper for k in ["TV", "BRAVIA", "VIZIO", "SAMSUNG", "LG", "ROKU", "FIRE", "SMARTVIEW", "KDL-"]):
        return "tv"
    if any(k in name_upper for k in ["HEADPHONE", "EARBUD", "BOSE", "SONY", "BEATS", "AUDIO", "AIRPOD", "JBL", "SENNHEISER"]):
        return "headphone"
    if any(k in name_upper for k in ["DASHCAM", "DASH CAM", "DVR", "70MAI", "VIOFO", "GARMIN DASH"]):
        return "dashcam"
    if any(k in name_upper for k in ["CAM", "SURVEILLANCE", "SECURITY", "NEST", "RING", "ARLO", "HIKVISION", "DAHUA", "REOLINK"]):
        return "camera"
    if any(k in name_upper for k in ["WATCH", "FITBIT", "GARMIN", "WHOOP"]):
        return "iot"
    return original_type

@app.route('/api/geocode')
def api_geocode():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({"error": "Missing query parameter"}), 400
    try:
        headers = {'User-Agent': 'WireTapper-SignalIntelligence/1.0'}
        r = requests.get(
            'https://nominatim.openstreetmap.org/search',
            params={'q': query, 'format': 'json', 'polygon_geojson': 1, 'limit': 1},
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            if data and len(data) > 0:
                item = data[0]
                bbox = [float(x) for x in item.get('boundingbox', [])]
                return jsonify({
                    "found": True,
                    "display_name": item.get('display_name'),
                    "lat": float(item.get('lat')),
                    "lon": float(item.get('lon')),
                    "boundingbox": bbox,  # [minLat, maxLat, minLon, maxLon]
                    "geojson": item.get('geojson')
                })
        return jsonify({"found": False, "message": "Location not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def scan_iot_devices(lat, lon, radius_km=5, use_shodan=True, use_censys=True, category='all'):
    """
    Scans for real IoT, SCADA, industrial devices, and exposed cameras in the target area
    using live Shodan API and Censys Search API v2. Strictly no simulated or fake data.
    """
    devices = []
    shodan_status = "Disabled (Switch OFF)" if not use_shodan else "Skipped (No Key)"
    censys_status = "Disabled (Switch OFF)" if not use_censys else "Skipped (No Key)"

    # 1. Shodan Host / Geo Search (if switch is ON)
    if use_shodan and SHODAN_API_KEY and SHODAN_API_KEY.strip() not in ['your_shodan_api_key', '']:
        try:
            shodan_query = f"geo:{lat},{lon},{radius_km}"
            res = requests.get(
                'https://api.shodan.io/shodan/host/search',
                params={'key': SHODAN_API_KEY.strip(), 'query': shodan_query, 'limit': 50},
                timeout=10
            )
            if res.status_code == 200:
                data = res.json()
                matches = data.get('matches', [])
                shodan_status = f"Success ({len(matches)} devices)"
                for m in matches:
                    ip = m.get('ip_str')
                    port = m.get('port', 80)
                    org = m.get('org') or m.get('isp') or 'ISP Host'
                    product = m.get('product') or m.get('_shodan', {}).get('module') or 'IoT Device'
                    raw_data = m.get('data', '')
                    dev_type = classify_device(f"{product} {raw_data}", "iot_device")
                    if 'cam' in product.lower() or 'rtsp' in raw_data.lower() or port in [554, 8000, 37777]:
                        dev_type = 'camera'
                    loc = m.get('location', {})
                    dev_lat = loc.get('latitude')
                    dev_lon = loc.get('longitude')
                    
                    # Accept only genuine coordinates
                    if dev_lat is None or dev_lon is None:
                        continue

                    devices.append({
                        "lat": float(dev_lat),
                        "lon": float(dev_lon),
                        "ssid": f"[{product.upper()}:{port}] {ip}",
                        "ip": ip,
                        "port": port,
                        "vendor": f"Shodan · {org} (Port {port})",
                        "signal": -50 - (port % 30),
                        "timestamp": m.get('timestamp') or datetime.now(timezone.utc).isoformat(),
                        "type": dev_type,
                        "source": "shodan",
                        "product": product,
                        "org": org,
                        "info": raw_data[:120].strip()
                    })
            else:
                try:
                    err_msg = res.json().get('error', res.text[:80])
                except Exception:
                    err_msg = res.text[:80]
                shodan_status = f"HTTP {res.status_code}: {err_msg}"
        except Exception as e:
            shodan_status = f"Error: {str(e)[:80]}"

    # 2. Censys Search API v2 (if switch is ON)
    if (use_censys and CENSYS_API_ID and CENSYS_API_SECRET and 
        CENSYS_API_ID.strip() not in ['your_censys_api_id', ''] and 
        CENSYS_API_SECRET.strip() not in ['your_censys_api_secret', '']):
        try:
            delta = radius_km / 111.0 # 1 deg lat ~= 111 km
            lat_min = round(lat - delta, 4)
            lat_max = round(lat + delta, 4)
            lon_min = round(lon - delta, 4)
            lon_max = round(lon + delta, 4)
            censys_query = f"location.coordinates.latitude:[{lat_min} TO {lat_max}] AND location.coordinates.longitude:[{lon_min} TO {lon_max}]"
            
            c_res = requests.get(
                'https://search.censys.io/api/v2/hosts/search',
                params={'q': censys_query, 'per_page': 50},
                auth=(CENSYS_API_ID.strip(), CENSYS_API_SECRET.strip()),
                headers={'Accept': 'application/json'},
                timeout=10
            )
            if c_res.status_code == 200:
                c_data = c_res.json()
                hits = c_data.get('result', {}).get('hits', [])
                censys_status = f"Success ({len(hits)} hosts)"
                for h in hits:
                    ip = h.get('ip')
                    services = h.get('services', [])
                    main_svc = services[0] if services else {}
                    port = main_svc.get('port', 80)
                    svc_name = main_svc.get('service_name', 'HTTP')
                    as_info = h.get('autonomous_system', {}).get('name') or 'Telecom AS'
                    coords = h.get('location', {}).get('coordinates', {})
                    dev_lat = coords.get('latitude')
                    dev_lon = coords.get('longitude')
                    
                    # Accept only genuine coordinates
                    if dev_lat is None or dev_lon is None:
                        continue
                    
                    dev_type = 'iot_device'
                    if 'rtsp' in svc_name.lower() or port in [554, 8000, 37777]:
                        dev_type = 'camera'

                    devices.append({
                        "lat": float(dev_lat),
                        "lon": float(dev_lon),
                        "ssid": f"[CENSYS:{svc_name.upper()}:{port}] {ip}",
                        "ip": ip,
                        "port": port,
                        "vendor": f"Censys.io · {as_info} ({svc_name})",
                        "signal": -52 - (port % 28),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": dev_type,
                        "source": "censys",
                        "product": svc_name,
                        "org": as_info,
                        "info": f"Protocol: {svc_name} on Port {port} · AS: {as_info}"
                    })
            else:
                try:
                    err_msg = c_res.json().get('error', c_res.text[:80])
                except Exception:
                    err_msg = c_res.text[:80]
                censys_status = f"HTTP {c_res.status_code}: {err_msg}"
        except Exception as e:
            censys_status = f"Error: {str(e)[:80]}"

    # Optional category filter (applied only to genuine devices)
    if category and category != 'all':
        devices = [d for d in devices if category.lower() in d.get('type', '').lower() or category.lower() in d.get('product', '').lower()]

    return {
        "devices": devices,
        "shodan_status": shodan_status,
        "censys_status": censys_status,
        "use_shodan": use_shodan,
        "use_censys": use_censys,
        "count": len(devices),
        "mode": "iot"
    }

@app.route('/api/iot/scan', methods=['GET', 'POST'])
def api_iot_scan():
    if request.method == 'POST':
        data = request.get_json() or {}
        lat = float(data.get('lat', 51.505))
        lon = float(data.get('lon', -0.09))
        radius = float(data.get('radius', 5))
        use_shodan = bool(data.get('shodan', True))
        use_censys = bool(data.get('censys', True))
        category = str(data.get('category', 'all'))
    else:
        lat = request.args.get('lat', default=51.505, type=float)
        lon = request.args.get('lon', default=-0.09, type=float)
        radius = request.args.get('radius', default=5, type=float)
        use_shodan = request.args.get('shodan', 'true').lower() in ['true', '1', 'yes']
        use_censys = request.args.get('censys', 'true').lower() in ['true', '1', 'yes']
        category = request.args.get('category', 'all')
    
    return jsonify(scan_iot_devices(lat, lon, radius, use_shodan, use_censys, category))

@app.route('/nearby')
def nearby():
    lat = request.args.get('lat', type=float)
    lon = request.args.get('lon', type=float)
    mode = request.args.get('mode', 'wifi') # 'wifi', 'cell', 'bluetooth', 'sdr', or 'iot'
    
    if lat is None or lon is None:
        return jsonify({"error": "Missing coordinates"}), 400

    if mode == 'iot':
        use_shodan = request.args.get('shodan', 'true').lower() in ['true', '1', 'yes']
        use_censys = request.args.get('censys', 'true').lower() in ['true', '1', 'yes']
        radius = request.args.get('radius', default=5, type=float)
        category = request.args.get('category', 'all')
        return jsonify(scan_iot_devices(lat, lon, radius, use_shodan, use_censys, category))

    devices = []
    
    if mode == 'sdr':
        # Hardware facts only. WireTapper detects an attached SDR receiver; it
        # does not capture RF, so no spectrum "devices" are synthesised here.
        sdr_info = check_usb_sdr_status()
        return jsonify({
            "devices": [],
            "sdr_status": sdr_info,
            "mode": "sdr",
            "note": ("SDR mode reports the attached receiver hardware. WireTapper performs no RF "
                     "capture, so no signal entries are generated.")
        })
    elif mode == 'bluetooth':
        # Wigle Bluetooth API call
        try:
            wigle_response = requests.get(
                'https://api.wigle.net/api/v2/bluetooth/search',
                params={'latrange1': lat-0.01, 'latrange2': lat+0.01, 'longrange1': lon-0.01, 'longrange2': lon+0.01},
                auth=(WIGLE_API_NAME, WIGLE_API_TOKEN),
                timeout=10
            )
            if wigle_response.status_code == 200:
                for device in wigle_response.json().get('results', []):
                    name = device.get('name') or device.get('netid')
                    original_type = "bluetooth"
                    classified_type = classify_device(name, original_type)
                    
                    devices.append({
                        "lat": device.get('trilat'),
                        "lon": device.get('trilong'),
                        "ssid": name,
                        "bssid": device.get('netid'),
                        "vendor": device.get('type') or ("Bluetooth Node" if classified_type == "bluetooth" else classified_type.replace('_', ' ').title()),
                        "signal": device.get('level'),
                        "timestamp": device.get('lastupdt'),
                        "type": classified_type
                    })
            else:
                print(f"Wigle BT error: {wigle_response.status_code} - {wigle_response.text}")
        except Exception as e:
            print(f"Wigle BT exception: {str(e)}")
    elif mode == 'cell':
        # Dedicated Cell Tower Mode: ONLY Cell Towers from WiGLE and OpenCellID (NO WiFi)
        # 1. WiGLE Cell Tower API
        try:
            w_res = requests.get(
                'https://api.wigle.net/api/v2/cell/search',
                params={'latrange1': lat-0.015, 'latrange2': lat+0.015, 'longrange1': lon-0.015, 'longrange2': lon+0.015},
                auth=(WIGLE_API_NAME, WIGLE_API_TOKEN),
                timeout=10
            )
            if w_res.status_code == 200:
                for cell in w_res.json().get('results', []):
                    gentype = cell.get('gentype') or 'GSM'
                    cid = str(cell.get('id', 'CellTower'))
                    loc_desc = cell.get('road') or cell.get('city') or 'Cellular Mast'
                    devices.append({
                        "lat": float(cell.get('trilat')),
                        "lon": float(cell.get('trilong')),
                        "ssid": f"WiGLE Cell [{gentype}] {cid}",
                        "cell_id": cid,
                        "vendor": f"WiGLE Cell ({gentype}) · {loc_desc}",
                        "signal": cell.get('qos', -68) if cell.get('qos') is not None else -68,
                        "timestamp": cell.get('lastupdt'),
                        "type": "cell_tower",
                        "source": "wigle",
                        "radio": gentype
                    })
            else:
                print(f"WiGLE cell error: {w_res.status_code} - {w_res.text[:100]}")
        except Exception as e:
            print(f"WiGLE cell exception: {e}")

        # 2. OpenCellID API
        try:
            # First try official opencellid getInArea with API key
            r_ocid = requests.get(
                'http://opencellid.org/cell/getInArea',
                params={
                    'key': OPENCELLID_API_KEY,
                    'BBOX': f"{lat-0.015},{lon-0.015},{lat+0.015},{lon+0.015}",
                    'format': 'json'
                },
                timeout=10
            )
            ocid_added = 0
            if r_ocid.status_code == 200:
                try:
                    ocid_json = r_ocid.json()
                    cells = ocid_json.get('cells', [])
                    for c in cells:
                        cid = str(c.get('cellid', 'Unknown'))
                        radio = (c.get('radio') or 'LTE').upper()
                        mcc = c.get('mcc', '')
                        mnc = c.get('mnc', '')
                        lac = c.get('lac', '')
                        devices.append({
                            "lat": float(c.get('lat')),
                            "lon": float(c.get('lon')),
                            "ssid": f"OpenCellID [{radio}] CID:{cid}",
                            "cell_id": cid,
                            "vendor": f"OpenCellID · MCC:{mcc} MNC:{mnc} LAC:{lac}",
                            "signal": c.get('averageSignalStrength') or -65,
                            "type": "cell_tower",
                            "source": "opencellid",
                            "radio": radio
                        })
                        ocid_added += 1
                except Exception as ex:
                    print("OpenCellID JSON parse err:", ex)

            # If no cells added from primary endpoint, try public Ajax endpoint
            if ocid_added == 0:
                r_ajax = requests.get(
                    'https://www.opencellid.org/ajax/getCells.php',
                    params={'bbox': f"{lon-0.015},{lat-0.015},{lon+0.015},{lat+0.015}"},
                    timeout=10
                )
                if r_ajax.status_code == 200:
                    features = r_ajax.json().get('features', [])
                    for feat in features:
                        props = feat.get('properties', {})
                        geom = feat.get('geometry', {})
                        coords = geom.get('coordinates', [0, 0])
                        radio = (props.get('radio') or 'GSM').upper()
                        mcc = props.get('mcc', '')
                        net = props.get('net', '')
                        area = props.get('area', '')
                        cid = str(props.get('cellid') or props.get('unit') or f"{mcc}-{net}-{area}")
                        devices.append({
                            "lat": float(coords[1]),
                            "lon": float(coords[0]),
                            "ssid": f"OpenCellID [{radio}] CID:{cid}",
                            "cell_id": cid,
                            "vendor": f"OpenCellID · MCC:{mcc} MNC:{net} LAC:{area}",
                            "signal": -65,
                            "timestamp": props.get('updated'),
                            "type": "cell_tower",
                            "source": "opencellid",
                            "radio": radio
                        })
        except Exception as e:
            print(f"OpenCellID exception: {e}")
    else:
        # Standard WiFi/Cell/IoT Logic
        # Wigle API call
        try:
            wigle_response = requests.get(
                'https://api.wigle.net/api/v2/network/search',
                params={'latrange1': lat-0.01, 'latrange2': lat+0.01, 'longrange1': lon-0.01, 'longrange2': lon+0.01},
                auth=(WIGLE_API_NAME, WIGLE_API_TOKEN),
                timeout=10
            )
            if wigle_response.status_code == 200:
                for network in wigle_response.json().get('results', []):
                    name = network.get('ssid')
                    original_type = "router"
                    classified_type = classify_device(name, original_type)

                    devices.append({
                        "lat": network.get('trilat'),
                        "lon": network.get('trilong'),
                        "ssid": name,
                        "bssid": network.get('netid'),
                        "vendor": network.get('vendor'),
                        "signal": network.get('level'),
                        "timestamp": network.get('lastupdt'),
                        "type": classified_type
                    })
            else:
                print(f"Wigle error: {wigle_response.status_code} - {wigle_response.text}")
        except Exception as e:
            print(f"Wigle exception: {str(e)}")

        # OpenCellID API call
        try:
            opencell_response = requests.get(
                'https://us1.unwiredlabs.com/v2/process.php',
                json={
                    "token": OPENCELLID_API_KEY,
                    "lat": lat,
                    "lon": lon,
                    "address": 0
                },
                timeout=10
            )
            if opencell_response.status_code == 200:
                data = opencell_response.json()
                if data.get('status') == 'ok':
                    for cell in data.get('cells', []):
                        devices.append({
                            "lat": cell.get('lat'),
                            "lon": cell.get('lon'),
                            "cell_id": str(cell.get('cellid')),
                            "signal": cell.get('signal'),
                            "accuracy": cell.get('accuracy'),
                            "timestamp": cell.get('updated'),
                            "type": "cell_tower",
                            "source": "opencellid"
                        })
                else:
                    print(f"OpenCellID API error: {data.get('message', 'Unknown error')}")
            else:
                print(f"OpenCellID HTTP error: {opencell_response.status_code} - {opencell_response.text}")
        except Exception as e:
            print(f"OpenCellID exception: {str(e)}")

        # Shodan API call
        if SHODAN_API_KEY:
            try:
                shodan_response = requests.get(
                    'https://api.shodan.io/shodan/host/search',
                    params={'key': SHODAN_API_KEY, 'query': f'geo:{lat},{lon},1', 'limit': 5},
                    timeout=10
                )
                if shodan_response.status_code == 200:
                    for banner in shodan_response.json().get('matches', []):
                        ip = banner['ip_str']
                        info = banner.get('data', '')
                        classified_type = classify_device(info, "iot_device")

                        devices.append({
                            "lat": banner['location']['latitude'],
                            "lon": banner['location']['longitude'],
                            "ip": ip,
                            "info": info[:50],
                            "type": classified_type
                        })
            except Exception as e:
                print(f"Shodan exception: {str(e)}")

    return jsonify({"devices": devices})

@app.route('/api/geo/towers')
def get_towers():
    try:
        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        
        if not lat or not lon:
            lat = 51.505
            lon = -0.09

        # Calculate Bounding Box (approx 5-10km radius)
        # 1 deg lat ~= 111km. 0.05 ~= 5.5km
        min_lat = lat - 0.05
        max_lat = lat + 0.05
        min_lon = lon - 0.05
        max_lon = lon + 0.05
        bbox = f"{min_lat},{min_lon},{max_lat},{max_lon}"

        # Using OpenCellID 'getInArea' API
        # Note: 'pk' tokens are typically UnwiredLabs, but user requested opencellid.org.
        # If the key is cross-compatible or this is the intended endpoint:
        response = requests.get(
            'http://opencellid.org/cell/getInArea',
            params={
                "key": OPENCELLID_API_KEY,
                "BBOX": bbox,
                "format": "json"
            }
        )
        
        if response.status_code == 200:
            # API might return JSON if format=json is supported and valid
            try:
                data = response.json()
            except:
                # Fallback if text/csv
                return jsonify({"error": "API returned non-JSON", "details": response.text[:100]})

            towers = []
            # OpenCellID usually returns { "cells": [ ... ] } or just a list?
            # Adjusting parsing based on common OpenCellID formatting
            cells = data.get('cells', []) if isinstance(data, dict) else data
            
            if isinstance(cells, list):
                for cell in cells:
                    towers.append({
                        "id": str(cell.get('cellid', 'Unknown')),
                        "lat": float(cell.get('lat')),
                        "lon": float(cell.get('lon')),
                        "lac": cell.get('lac', 0),
                        "mcc": cell.get('mcc', 0),
                        "mnc": cell.get('mnc', 0),
                        "signal": cell.get('signal', 0), # Often not present in static DB
                        "radio": cell.get('radio', 'gsm')
                    })
            
            return jsonify(towers)
            
        else:
            return jsonify({"error": f"Upstream API error: {response.status_code}", "details": response.text[:100]}), 502

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/geo/celltower')
def get_celltower_click():
    try:
        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        
        if not lat or not lon:
            return jsonify({"error": "Missing coordinates"}), 400

        # Small BBOX for specific location (approx 2km radius)
        # BBOX format for OpenCellID ajax: min_lon,min_lat,max_lon,max_lat
        min_lat = lat - 0.01
        max_lat = lat + 0.01
        min_lon = lon - 0.01
        max_lon = lon + 0.01
        bbox = f"{min_lon},{min_lat},{max_lon},{max_lat}"

        # Using the endpoint provided by user
        # This appears to be an internal/public web endpoint
        response = requests.get(
            'https://www.opencellid.org/ajax/getCells.php',
            params={
                "bbox": bbox
                # API Key might not be needed for this specific AJAX endpoint, 
                # or it uses cookies/referer. We try without first as per user URL.
            }
        )
        
        if response.status_code == 200:
            try:
                data = response.json()
            except:
                return jsonify({"error": "API returned non-JSON", "details": response.text[:100]})

            towers = []
            
            # The AJAX endpoint returns GeoJSON: { "type": "FeatureCollection", "features": [ ... ] }
            features = data.get('features', []) if isinstance(data, dict) else []
            
            for feature in features:
                props = feature.get('properties', {})
                geom = feature.get('geometry', {})
                coords = geom.get('coordinates', [0, 0]) # [lon, lat]
                
                # Note: 'cellid' might be missing in this public aggregate view
                # Mapping: mcc=mcc, net=mnc, area=lac/tac
                towers.append({
                    "id": str(props.get('cellid', props.get('unit', 'Unknown'))),
                    "lat": float(coords[1]),
                    "lon": float(coords[0]),
                    "lac": props.get('area', 0),
                    "mcc": props.get('mcc', 0),
                    "mnc": props.get('net', 0),
                    "signal": props.get('samples', 0), # Using samples as proxy for 'strength/reliability'
                    "radio": props.get('radio', 'gsm')
                })
            
            return jsonify(towers)
        else:
            return jsonify({"error": f"Upstream API error: {response.status_code}", "details": response.text[:100]}), 502

    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route('/searchzz')
def search():
    search_type = request.args.get('type')
    query = request.args.get('query')
    mode = request.args.get('mode', 'wifi')
    if not search_type or not query:
        return jsonify({"error": "Missing search parameters"}), 400

    devices = []

    if mode == 'sdr':
        sdr_info = check_usb_sdr_status()
        return jsonify({
            "devices": [],
            "sdr_status": sdr_info,
            "query": query,
            "mode": "sdr",
            "note": ("SDR mode reports the attached receiver hardware. WireTapper performs no RF "
                     "capture, so no signal entries are generated.")
        })

    if search_type == 'location':
        try:
            lat, lon = map(float, query.split(','))
            if mode == 'cell':
                # WiGLE Cell Search
                try:
                    w_res = requests.get(
                        'https://api.wigle.net/api/v2/cell/search',
                        params={'latrange1': lat-0.015, 'latrange2': lat+0.015, 'longrange1': lon-0.015, 'longrange2': lon+0.015},
                        auth=(WIGLE_API_NAME, WIGLE_API_TOKEN),
                        timeout=10
                    )
                    if w_res.status_code == 200:
                        for cell in w_res.json().get('results', []):
                            gentype = cell.get('gentype') or 'GSM'
                            cid = str(cell.get('id', 'CellTower'))
                            road = cell.get('road') or cell.get('city') or 'Cellular Mast'
                            devices.append({
                                "lat": float(cell.get('trilat')),
                                "lon": float(cell.get('trilong')),
                                "ssid": f"WiGLE Cell [{gentype}] {cid}",
                                "cell_id": cid,
                                "vendor": f"WiGLE Cell ({gentype}) · {road}",
                                "signal": cell.get('qos', -68) if cell.get('qos') is not None else -68,
                                "timestamp": cell.get('lastupdt'),
                                "type": "cell_tower",
                                "source": "wigle",
                                "radio": gentype
                            })
                except Exception as e:
                    print(f"WiGLE cell search error: {e}")

                # OpenCellID
                try:
                    r_ocid = requests.get(
                        'http://opencellid.org/cell/getInArea',
                        params={'key': OPENCELLID_API_KEY, 'BBOX': f"{lat-0.015},{lon-0.015},{lat+0.015},{lon+0.015}", 'format': 'json'},
                        timeout=10
                    )
                    if r_ocid.status_code == 200 and r_ocid.json().get('cells'):
                        for c in r_ocid.json().get('cells', []):
                            cid = str(c.get('cellid', 'Unknown'))
                            radio = (c.get('radio') or 'LTE').upper()
                            devices.append({
                                "lat": float(c.get('lat')),
                                "lon": float(c.get('lon')),
                                "ssid": f"OpenCellID [{radio}] CID:{cid}",
                                "cell_id": cid,
                                "vendor": f"OpenCellID · MCC:{c.get('mcc')} MNC:{c.get('mnc')} LAC:{c.get('lac')}",
                                "signal": c.get('averageSignalStrength') or -65,
                                "type": "cell_tower",
                                "source": "opencellid",
                                "radio": radio
                            })
                    else:
                        r_ajax = requests.get(
                            'https://www.opencellid.org/ajax/getCells.php',
                            params={'bbox': f"{lon-0.015},{lat-0.015},{lon+0.015},{lat+0.015}"},
                            timeout=10
                        )
                        if r_ajax.status_code == 200:
                            for feat in r_ajax.json().get('features', []):
                                props = feat.get('properties', {})
                                geom = feat.get('geometry', {})
                                coords = geom.get('coordinates', [0, 0])
                                radio = (props.get('radio') or 'GSM').upper()
                                cid = str(props.get('cellid') or props.get('unit') or 'BTS')
                                devices.append({
                                    "lat": float(coords[1]),
                                    "lon": float(coords[0]),
                                    "ssid": f"OpenCellID [{radio}] CID:{cid}",
                                    "cell_id": cid,
                                    "vendor": f"OpenCellID · MCC:{props.get('mcc')} MNC:{props.get('net')} LAC:{props.get('area')}",
                                    "signal": -65,
                                    "timestamp": props.get('updated'),
                                    "type": "cell_tower",
                                    "source": "opencellid",
                                    "radio": radio
                                })
                except Exception as e:
                    print(f"OpenCellID search error: {e}")
            else:
                # Standard WiGLE Network Search
                try:
                    wigle_response = requests.get(
                        'https://api.wigle.net/api/v2/network/search',
                        params={'latrange1': lat-0.01, 'latrange2': lat+0.01, 'longrange1': lon-0.01, 'longrange2': lon+0.01},
                        auth=(WIGLE_API_NAME, WIGLE_API_TOKEN),
                        timeout=10
                    )
                    if wigle_response.status_code == 200:
                        for network in wigle_response.json().get('results', []):
                            devices.append({
                                "lat": network.get('trilat'),
                                "lon": network.get('trilong'),
                                "ssid": network.get('ssid'),
                                "bssid": network.get('netid'),
                                "vendor": network.get('vendor'),
                                "signal": network.get('level'),
                                "timestamp": network.get('lastupdt'),
                                "type": "router"
                            })
                    else:
                        print(f"Wigle location error: {wigle_response.status_code} - {wigle_response.text}")
                except Exception as e:
                    print(f"Wigle location exception: {str(e)}")

                # OpenCellID API call
                try:
                    opencell_response = requests.get(
                        'https://us1.unwiredlabs.com/v2/process.php',
                        json={
                            "token": OPENCELLID_API_KEY,
                            "lat": lat,
                            "lon": lon,
                            "address": 0
                        },
                        timeout=10
                    )
                    if opencell_response.status_code == 200:
                        data = opencell_response.json()
                        if data.get('status') == 'ok':
                            for cell in data.get('cells', []):
                                devices.append({
                                    "lat": cell.get('lat'),
                                    "lon": cell.get('lon'),
                                    "cell_id": str(cell.get('cellid')),
                                    "signal": cell.get('signal'),
                                    "accuracy": cell.get('accuracy'),
                                    "timestamp": cell.get('updated'),
                                    "type": "cell_tower",
                                    "source": "opencellid"
                                })
                        else:
                            print(f"OpenCellID location error: {data.get('message', 'Unknown error')}")
                    else:
                        print(f"OpenCellID location HTTP error: {opencell_response.status_code} - {opencell_response.text}")
                except Exception as e:
                    print(f"OpenCellID location exception: {str(e)}")
        except:
            return jsonify({"error": "Invalid location format"})

    elif search_type == 'bssid':
        try:
            wigle_response = requests.get(
                'https://api.wigle.net/api/v2/network/search',
                params={'netid': query},
                auth=(WIGLE_API_NAME, WIGLE_API_TOKEN)
            )
            if wigle_response.status_code == 200:
                for network in wigle_response.json().get('results', []):
                    devices.append({
                        "lat": network.get('trilat'),
                        "lon": network.get('trilong'),
                        "ssid": network.get('ssid'),
                        "bssid": network.get('netid'),
                        "vendor": network.get('vendor'),
                        "signal": network.get('level'),
                        "timestamp": network.get('lastupdt'),
                        "type": "router"
                    })
            else:
                print(f"Wigle BSSID error: {wigle_response.status_code} - {wigle_response.text}")
        except Exception as e:
            print(f"Wigle BSSID exception: {str(e)}")

    elif search_type == 'ssid':
        try:
            wigle_response = requests.get(
                'https://api.wigle.net/api/v2/network/search',
                params={'ssid': query},
                auth=(WIGLE_API_NAME, WIGLE_API_TOKEN)
            )
            if wigle_response.status_code == 200:
                for network in wigle_response.json().get('results', []):
                    devices.append({
                        "lat": network.get('trilat'),
                        "lon": network.get('trilong'),
                        "ssid": network.get('ssid'),
                        "bssid": network.get('netid'),
                        "vendor": network.get('vendor'),
                        "signal": network.get('level'),
                        "timestamp": network.get('lastupdt'),
                        "type": "router"
                    })
            else:
                print(f"Wigle SSID error: {wigle_response.status_code} - {wigle_response.text}")
        except Exception as e:
            print(f"Wigle SSID exception: {str(e)}")

    elif search_type == 'network':
        if SHODAN_API_KEY:
            try:
                shodan_response = requests.get(
                    'https://api.shodan.io/shodan/host/search',
                    params={'key': SHODAN_API_KEY, 'query': query}
                )
                if shodan_response.status_code == 200:
                    for host in shodan_response.json().get('matches', []):
                        devices.append({
                            "lat": host.get('location', {}).get('latitude'),
                            "lon": host.get('location', {}).get('longitude'),
                            "ip": host.get('ip_str'),
                            "vendor": host.get('org'),
                            "type": host.get('product', 'iot')
                        })
                else:
                    print(f"Shodan search error: {shodan_response.status_code} - {shodan_response.text}")
            except Exception as e:
                print(f"Shodan search exception: {str(e)}")
        else:
            print("Shodan search skipped: No API key provided")

    return jsonify({"devices": devices})

@app.route('/api/upload/preview', methods=['POST'])
def api_upload_preview():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part in upload request'}), 400
    
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected for ingestion'}), 400

    orig_filename = secure_filename(file.filename) or f"telemetry_{int(time.time())}.csv"
    timestamp = int(time.time())
    saved_filename = f"{timestamp}_{orig_filename}"
    saved_path = os.path.join(UPLOAD_FOLDER, saved_filename)
    
    try:
        file.save(saved_path)
        preview_data = telemetry_importer.preview_file(saved_path)
        if preview_data.get('status') == 'error':
            return jsonify(preview_data), 400
        return jsonify(preview_data)
    except Exception as e:
        print(f"File upload preview error: {e}")
        return jsonify({'status': 'error', 'message': f'Failed to parse file: {str(e)}'}), 500

@app.route('/api/upload/process', methods=['POST'])
def api_upload_process():
    data = request.get_json() or {}
    file_id = data.get('file_id')
    mappings = data.get('mappings', {})
    
    if not file_id:
        return jsonify({'status': 'error', 'message': 'file_id parameter is required'}), 400
    
    safe_file_id = secure_filename(file_id)
    file_path = os.path.join(UPLOAD_FOLDER, safe_file_id)
    
    if not os.path.exists(file_path):
        return jsonify({'status': 'error', 'message': f'File {safe_file_id} not found in uploads'}), 404
        
    try:
        result = telemetry_importer.process_file(file_path, mappings)
        if result.get('status') == 'error':
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        print(f"File upload process error: {e}")
        return jsonify({'status': 'error', 'message': f'Failed to ingest telemetry: {str(e)}'}), 500

@app.route('/api/upload/list', methods=['GET'])
def api_upload_list():
    try:
        files = []
        for f in os.listdir(UPLOAD_FOLDER):
            fp = os.path.join(UPLOAD_FOLDER, f)
            if os.path.isfile(fp) and not f.startswith('.'):
                parts = f.split('_', 1)
                clean_name = parts[1] if (len(parts) == 2 and parts[0].isdigit()) else f
                ts = int(parts[0]) if (len(parts) == 2 and parts[0].isdigit()) else int(os.path.getmtime(fp))
                files.append({
                    'file_id': f,
                    'name': clean_name,
                    'size': os.path.getsize(fp),
                    'timestamp': ts,
                    'ext': os.path.splitext(f)[1].lower()
                })
        files.sort(key=lambda x: x['timestamp'], reverse=True)
        return jsonify({'status': 'success', 'files': files})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ════════════════════════════════════════════════════════
# FLOCK SAFETY & ALPR SURVEILLANCE INTELLIGENCE ROUTES
# ════════════════════════════════════════════════════════

@app.route('/api/flock/datasets', methods=['GET'])
def api_flock_datasets():
    try:
        catalog = flock_manager.get_catalog()
        return jsonify({'status': 'success', 'catalog': catalog})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/flock/download', methods=['POST'])
def api_flock_download():
    data = request.get_json() or {}
    dataset_id = data.get('dataset_id')
    if not dataset_id:
        return jsonify({'status': 'error', 'message': 'dataset_id is required'}), 400
    try:
        res = flock_manager.download_dataset(dataset_id)
        status_code = 200 if res.get('status') == 'success' else 400
        return jsonify(res), status_code
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/flock/upload', methods=['POST'])
def api_flock_upload():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part in upload request'}), 400
    
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'}), 400

    orig_filename = secure_filename(file.filename) or f"flock_db_{int(time.time())}.csv"
    timestamp = int(time.time())
    saved_filename = f"{timestamp}_{orig_filename}"
    saved_path = os.path.join(flock_manager.FLOCK_DIR, saved_filename)
    
    try:
        file.save(saved_path)
        preview = flock_manager.preview_dataset(saved_filename, page=1, per_page=40)
        return jsonify({
            'status': 'success',
            'filename': saved_filename,
            'preview': preview
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to process file: {str(e)}'}), 500

@app.route('/api/flock/preview', methods=['GET'])
def api_flock_preview():
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'status': 'error', 'message': 'filename query parameter is required'}), 400
    
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 40))
    
    try:
        data = flock_manager.preview_dataset(filename, page=page, per_page=per_page)
        status_code = 200 if data.get('status') == 'success' else 404
        return jsonify(data), status_code
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/flock/search', methods=['GET'])
def api_flock_search():
    filename = request.args.get('filename')
    query = request.args.get('q', '')
    limit = int(request.args.get('limit', 500))
    
    if not filename:
        return jsonify({'status': 'error', 'message': 'filename query parameter is required'}), 400
        
    try:
        res = flock_manager.search_dataset(filename, query, limit=limit)
        return jsonify(res)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/flock/cameras', methods=['GET'])
def api_flock_cameras():
    filename = request.args.get('filename')
    limit = int(request.args.get('limit', 15000))
    
    if not filename:
        return jsonify({'status': 'error', 'message': 'filename query parameter is required'}), 400
        
    try:
        res = flock_manager.get_all_dataset_cameras(filename, limit=limit)
        status_code = 200 if res.get('status') == 'success' else 404
        return jsonify(res), status_code
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/flock/query', methods=['GET'])
def api_flock_query():
    """Query the local ALPR/Flock datasets by place instead of by proximity.

    GET /api/flock/query?region=FL&bbox=26.24,-80.90,27.05,-79.98&zip=334
    Optional: q=<text>, city=<name> (repeatable), lat/lon/radius, limit,
    strict=1 (drop rows whose dataset records no state), format=json|geojson|csv.
    Same engine as `wiretaper flock ...`.
    """
    try:
        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        radius = request.args.get('radius', type=float)
        result = sigint.flock_search(
            query=request.args.get('q') or request.args.get('query'),
            region=request.args.get('region') or request.args.get('state'),
            bbox=request.args.get('bbox'),
            cities=request.args.getlist('city'),
            zip_prefix=request.args.get('zip') or request.args.get('zip_prefix'),
            lat=lat, lon=lon, radius_km=radius,
            datasets=[d for d in request.args.getlist('dataset') if d],
            limit=min(request.args.get('limit', default=5000, type=int), 50000),
            strict_region=request.args.get('strict', 'false').lower() in ('1', 'true', 'yes'),
        )
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400

    fmt = (request.args.get('format') or 'json').lower()
    cameras = result['devices']
    if fmt == 'geojson':
        return jsonify(sigint.cameras_to_geojson(cameras))
    if fmt == 'csv':
        body = sigint.cameras_to_csv(cameras)
        return app.response_class(body, mimetype='text/csv', headers={
            'Content-Disposition': 'attachment; filename="flock_query.csv"'})
    return jsonify(result)


@app.route('/api/flock/delete', methods=['POST', 'DELETE'])
def api_flock_delete():
    data = request.get_json() or {}
    filename = data.get('filename') or request.args.get('filename')
    if not filename:
        return jsonify({'status': 'error', 'message': 'filename is required'}), 400
        
    try:
        res = flock_manager.delete_dataset(filename)
        return jsonify(res)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ════════════════════════════════════════════════════════
# BT SCAN — Bluetooth LE & RPA Radar Intelligence Module
# ════════════════════════════════════════════════════════

_BT_ENV_PATH_LOSS = {
    "free_space": 2.0,
    "outdoor": 2.2,
    "indoor": 3.0,
}
_BT_DEFAULT_REF_OFFSET = 59  # iBeacon standard: -59 dBm at 1m for 0 dBm TX
_BT_RSSI_WINDOW = 3           # sliding RSSI average window

def _bt_ah(irk: bytes, prand: bytes) -> bytes:
    """Bluetooth Core Spec ah() function (Vol 3, Part H, Section 2.2.2).
    AES-128-ECB(IRK, padding || prand) -> return last 3 bytes.
    ECB is mandated by the BT Core Spec for this single-block operation.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        plaintext = b'\x00' * 13 + prand
        cipher = Cipher(algorithms.AES(irk), modes.ECB())
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()
        return ct[-3:]
    except Exception as e:
        print(f"AES cipher error: {e}")
        return b''

def _bt_is_rpa(addr_bytes: bytes) -> bool:
    """RPA has top two bits of the most-significant byte == 01."""
    return len(addr_bytes) == 6 and (addr_bytes[0] >> 6) == 0b01

def _bt_resolve_rpa(irk: bytes, address: str) -> bool:
    """Resolve a MAC address string against an IRK using the Bluetooth ah() function.
    prand = first 3 octets, hash = last 3 octets.
    Returns True if ah(IRK, prand) == hash.
    """
    parts = address.replace("-", ":").split(":")
    if len(parts) != 6:
        return False
    try:
        addr_bytes = bytes(int(b, 16) for b in parts)
    except ValueError:
        return False
    if not _bt_is_rpa(addr_bytes):
        return False
    prand = addr_bytes[:3]
    expected_hash = addr_bytes[3:]
    return _bt_ah(irk, prand) == expected_hash

def _bt_estimate_distance(rssi: int, tx_power, env: str = "free_space"):
    """Estimate distance in meters using the log-distance path loss model.
    Derived from measured_power = tx_power - _BT_DEFAULT_REF_OFFSET (59 dB iBeacon offset).
    """
    if rssi == 0 or rssi is None:
        return None
    if tx_power is not None:
        measured_power = tx_power - _BT_DEFAULT_REF_OFFSET
    else:
        measured_power = -59
    n = _BT_ENV_PATH_LOSS.get(env, 2.0)
    try:
        return 10 ** ((measured_power - rssi) / (10 * n))
    except Exception:
        return None

# Live store: address -> device record (exact btrpa-scan format)
_BT_LIVE_STORE = {}          # address -> record dict
_BT_RSSI_HISTORY = {}        # address -> collections.deque of rssi ints
_BT_SEEN_COUNT = {}          # address -> times_seen int
_BT_TOTAL_DETECTIONS = 0     # total callback invocations
_BT_STORE_LOCK = threading.Lock()
_BT_SCANNER_STARTED = False
_BT_SCANNER_START_TIME = None

def _get_os_info():
    """Detects Linux distribution, identifying Kali Linux, Debian, etc."""
    info = {
        'os_name': 'Linux',
        'os_id': 'linux',
        'version': '',
        'is_kali': False,
        'kernel': platform.release(),
        'arch': platform.machine()
    }
    if os.path.exists('/etc/os-release'):
        try:
            with open('/etc/os-release') as f:
                for line in f:
                    if '=' in line:
                        k, v = line.strip().split('=', 1)
                        v = v.strip('"\'')
                        if k == 'PRETTY_NAME':
                            info['os_name'] = v
                        elif k == 'ID':
                            info['os_id'] = v
                        elif k == 'VERSION_ID':
                            info['version'] = v
        except Exception:
            pass
    if 'kali' in info['os_id'].lower() or 'kali' in info['os_name'].lower():
        info['is_kali'] = True
    return info

def _check_bluetooth_service():
    """Checks systemd and rfkill status for bluetooth."""
    active = False
    adapter_up = False
    rfkill_blocked = False
    
    try:
        res = subprocess.run(['systemctl', 'is-active', 'bluetooth'], capture_output=True, text=True, timeout=2)
        active = res.stdout.strip() == 'active'
    except Exception:
        pass

    try:
        res = subprocess.run(['rfkill', 'list', 'bluetooth'], capture_output=True, text=True, timeout=2)
        if 'Soft blocked: yes' in res.stdout or 'Hard blocked: yes' in res.stdout:
            rfkill_blocked = True
    except Exception:
        pass

    try:
        res = subprocess.run(['hciconfig', 'hci0'], capture_output=True, text=True, timeout=2)
        out = res.stdout
        adapter_up = 'UP RUNNING' in out or 'UP' in out
    except Exception:
        pass

    return {
        'service_active': active,
        'adapter_up': adapter_up,
        'rfkill_blocked': rfkill_blocked
    }

def _start_live_bt_scanner():
    global _BT_SCANNER_STARTED
    if _BT_SCANNER_STARTED:
        return
    _BT_SCANNER_STARTED = True

    def _scanner_worker():
        global _BT_TOTAL_DETECTIONS, _BT_SCANNER_START_TIME
        _BT_SCANNER_START_TIME = time.time()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _run_bleak():
            global _BT_TOTAL_DETECTIONS
            while True:
                try:
                    from bleak import BleakScanner

                    def _callback(device, adv):
                        global _BT_TOTAL_DETECTIONS
                        addr = (device.address or '').upper()
                        if not addr:
                            return

                        parts = addr.replace('-', ':').split(':')
                        is_rpa = False
                        if len(parts) == 6:
                            try:
                                b0 = int(parts[0], 16)
                                is_rpa = (b0 >> 6) == 0b01
                            except ValueError:
                                pass

                        with _BT_STORE_LOCK:
                            if addr not in _BT_RSSI_HISTORY:
                                _BT_RSSI_HISTORY[addr] = deque(maxlen=_BT_RSSI_WINDOW)
                            _BT_RSSI_HISTORY[addr].append(adv.rssi)
                            h = _BT_RSSI_HISTORY[addr]
                            avg_rssi = round(sum(h) / len(h))
                            _BT_SEEN_COUNT[addr] = _BT_SEEN_COUNT.get(addr, 0) + 1
                            times_seen = _BT_SEEN_COUNT[addr]
                            _BT_TOTAL_DETECTIONS += 1

                        mfr_parts = []
                        if adv.manufacturer_data:
                            for mfr_id, mfr_data in adv.manufacturer_data.items():
                                mfr_parts.append(f'0x{mfr_id:04X}:{mfr_data.hex()}')
                        manufacturer_data = '; '.join(mfr_parts)

                        service_uuids = ', '.join(adv.service_uuids) if adv.service_uuids else ''
                        dev_name = device.name or adv.local_name or 'Unknown'

                        tx_power = adv.tx_power
                        est_distance = _bt_estimate_distance(adv.rssi, tx_power, 'free_space')
                        if est_distance is not None:
                            est_distance = round(est_distance, 2)

                        record = {
                            'address':           addr,
                            'name':              dev_name,
                            'rssi':              adv.rssi,
                            'avg_rssi':          avg_rssi,
                            'tx_power':          tx_power if tx_power is not None else '',
                            'est_distance':      est_distance if est_distance is not None else '',
                            'manufacturer_data': manufacturer_data,
                            'service_uuids':     service_uuids,
                            'times_seen':        times_seen,
                            'last_seen':         time.strftime('%H:%M:%S'),
                            'resolved':          False,
                            'is_rpa':            is_rpa,
                            'timestamp':         time.strftime('%Y-%m-%dT%H:%M:%S'),
                            '_last_seen_epoch':  time.time(),
                        }

                        with _BT_STORE_LOCK:
                            _BT_LIVE_STORE[addr] = record
                            if len(_BT_LIVE_STORE) > 1000:
                                oldest = min(
                                    _BT_LIVE_STORE.keys(),
                                    key=lambda k: _BT_SEEN_COUNT.get(k, 0)
                                )
                                _BT_LIVE_STORE.pop(oldest, None)

                    scanner = BleakScanner(detection_callback=_callback)
                    await scanner.start()
                    while True:
                        await asyncio.sleep(5)
                        now = time.time()
                        with _BT_STORE_LOCK:
                            stale = [k for k, v in _BT_LIVE_STORE.items() if now - v.get('_last_seen_epoch', 0) > 60]
                            for k in stale:
                                _BT_LIVE_STORE.pop(k, None)
                except Exception as ex:
                    # When bluetooth service is not running or no adapter, sleep and retry (no fake data)
                    await asyncio.sleep(4)

        loop.run_until_complete(_run_bleak())

    t = threading.Thread(target=_scanner_worker, daemon=True)
    t.start()

# Automatically initialize bluetooth radar background scanner
_start_live_bt_scanner()

@app.route('/btscan')
def btscan():
    return render_template('btscan.html')

@app.route('/api/bluetooth/status', methods=['GET'])
def api_bluetooth_status():
    os_info = _get_os_info()
    svc = _check_bluetooth_service()
    return jsonify({
        'status': 'success',
        'os': os_info,
        'service': svc,
        'adapter_name': 'hci0'
    })

@app.route('/api/bluetooth/service_action', methods=['POST'])
def api_bluetooth_service_action():
    data = request.get_json() or {}
    action = data.get('action', 'start')
    sudo_password = data.get('password', '')

    cmds = []
    if action == 'start':
        cmds = [
            ['rfkill', 'unblock', 'bluetooth'],
            ['systemctl', 'start', 'bluetooth'],
            ['hciconfig', 'hci0', 'up']
        ]
    elif action == 'restart':
        cmds = [
            ['rfkill', 'unblock', 'bluetooth'],
            ['systemctl', 'restart', 'bluetooth'],
            ['hciconfig', 'hci0', 'up']
        ]
    elif action == 'stop':
        cmds = [['systemctl', 'stop', 'bluetooth']]
    else:
        return jsonify({'status': 'error', 'message': 'Unknown action'}), 400

    output_lines = []
    success = True

    for cmd in cmds:
        try:
            if sudo_password:
                full_cmd = ['sudo', '-S'] + cmd
                proc = subprocess.Popen(
                    full_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate(input=sudo_password + '\n', timeout=10)
                if proc.returncode != 0:
                    success = False
                    output_lines.append(f"{' '.join(cmd)} failed (code {proc.returncode}): {stderr.strip() or stdout.strip()}")
                else:
                    output_lines.append(f"✓ {' '.join(cmd)}: OK")
            else:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if proc.returncode != 0:
                    proc_sudo = subprocess.run(['sudo', '-n'] + cmd, capture_output=True, text=True, timeout=5)
                    if proc_sudo.returncode != 0:
                        success = False
                        output_lines.append(f"Sudo password required for {' '.join(cmd)}")
                    else:
                        output_lines.append(f"✓ {' '.join(cmd)}: OK")
                else:
                    output_lines.append(f"✓ {' '.join(cmd)}: OK")
        except Exception as e:
            success = False
            output_lines.append(f"Exception running {' '.join(cmd)}: {str(e)}")

    svc = _check_bluetooth_service()
    return jsonify({
        'status': 'success' if success else 'error',
        'message': '\n'.join(output_lines),
        'service': svc
    })

@app.route('/api/btscan/devices')
def api_btscan_devices():
    _start_live_bt_scanner()
    with _BT_STORE_LOCK:
        live_devices = sorted(
            list(_BT_LIVE_STORE.values()),
            key=lambda x: x.get('rssi', -100),
            reverse=True
        )
        total_detections = _BT_TOTAL_DETECTIONS
        start_time = _BT_SCANNER_START_TIME

    elapsed = round(time.time() - start_time, 1) if start_time else 0
    svc = _check_bluetooth_service()

    return jsonify({
        'status':            'success',
        'adapter_up':        svc['adapter_up'],
        'service_active':    svc['service_active'],
        'adapter_name':      'hci0',
        'devices':           live_devices,
        'total':             len(live_devices),
        'total_detections':  total_detections,
        'rpa_count':         sum(1 for d in live_devices if d.get('is_rpa')),
        'elapsed':           elapsed,
        'scanning':          True,
    })

@app.route('/api/btscan/test_devices')
def api_btscan_test_devices():
    _start_live_bt_scanner()
    with _BT_STORE_LOCK:
        return jsonify(list(_BT_LIVE_STORE.values()))

@app.route('/api/btscan/resolve_irk', methods=['POST'])
@app.route('/api/btscan/resolve_irk_v2', methods=['POST'])
def api_btscan_resolve_irk():
    data = request.get_json() or {}
    irk_hex = data.get('irk', '').strip()
    mac_address = data.get('mac', '').strip().upper()

    if not irk_hex or not mac_address:
        return jsonify({'status': 'error', 'error': 'Missing IRK or MAC address'}), 400

    clean_irk = irk_hex.lower().replace('0x', '').replace(':', '').replace('-', '')
    if len(clean_irk) != 32:
        return jsonify({'status': 'error', 'error': 'IRK must be 32 hex characters (16 bytes)'}), 400

    try:
        irk_bytes = bytes.fromhex(clean_irk)
    except ValueError:
        return jsonify({'status': 'error', 'error': 'Invalid hex in IRK'}), 400

    matched = _bt_resolve_rpa(irk_bytes, mac_address)

    parts = mac_address.replace('-', ':').split(':')
    is_rpa = False
    if len(parts) == 6:
        try:
            b0 = int(parts[0], 16)
            is_rpa = (b0 >> 6) == 0b01
        except ValueError:
            pass

    return jsonify({
        'status':     'success',
        'matched':    matched,
        'is_rpa':     is_rpa,
        'mac':        mac_address,
        'irk_masked': clean_irk[:4] + '....' + clean_irk[-4:],
    })

@app.route('/api/btscan/stats')
def api_btscan_stats():
    with _BT_STORE_LOCK:
        unique = len(_BT_LIVE_STORE)
        total = _BT_TOTAL_DETECTIONS
        start_time = _BT_SCANNER_START_TIME

    elapsed = round(time.time() - start_time, 1) if start_time else 0
    svc = _check_bluetooth_service()

    return jsonify({
        'adapter':          'hci0',
        'bus':              'USB Primary',
        'service_active':   svc['service_active'],
        'adapter_up':       svc['adapter_up'],
        'state':            'ACTIVE' if _BT_SCANNER_STARTED else 'IDLE',
        'mode':             'BLE PASSIVE SCAN',
        'rpa_resolution':   'AES-128-ECB ah() — Bluetooth Core Spec Vol 3 Part H',
        'unique_devices':   unique,
        'total_detections':  total,
        'elapsed':          elapsed,
        'scanning':         _BT_SCANNER_STARTED,
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
