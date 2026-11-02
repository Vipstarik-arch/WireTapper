import os
import re
import io
import csv
import gzip
import json
import sqlite3
import requests
import xml.etree.ElementTree as ET
from datetime import datetime

# Path for downloaded and uploaded Flock datasets
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FLOCK_DIR = os.path.join(BASE_DIR, 'uploads', 'flock')
os.makedirs(FLOCK_DIR, exist_ok=True)

# Curated catalog of verified Flock Safety & ALPR datasets
CATALOG = [
    {
        "id": "deflock_ca",
        "name": "DeFlock California ALPR Network",
        "filename": "deflock_california_cameras.geojson",
        "format": "GEOJSON",
        "source": "DeFlock (maps.deflock.org)",
        "source_url": "https://maps.deflock.org/?l",
        "download_url": "https://data.dontgetflocked.com/cameras-ca.geojson.gz",
        "is_gzip": True,
        "description": "Verified OpenStreetMap surveillance camera nodes across California mapped by DeFlock contributors."
    },
    {
        "id": "deflock_us_master",
        "name": "DeFlock USA/Global Master ALPR DB",
        "filename": "deflock_master_cameras.geojson",
        "format": "GEOJSON",
        "source": "DeFlock (maps.deflock.org)",
        "source_url": "https://maps.deflock.org/?l",
        "download_url": "https://data.dontgetflocked.com/cameras.geojson.gz",
        "is_gzip": True,
        "description": "Complete global database of Flock Safety & ALPR surveillance cameras mapped by DeFlock."
    },
    {
        "id": "pigvision_akron",
        "name": "Pigvision Flock Cameras (Akron, OH)",
        "filename": "Pigvision.csv",
        "format": "CSV",
        "source": "colonelpanichacks/flock-you",
        "source_url": "https://github.com/colonelpanichacks/flock-you/blob/main/datasets/Pigvision.csv",
        "download_url": "https://raw.githubusercontent.com/colonelpanichacks/flock-you/main/datasets/Pigvision.csv",
        "is_gzip": False,
        "description": "Flock Safety cameras with street intersections, configuration types, and Google Maps direct links."
    },
    {
        "id": "maximum_dots",
        "name": "Maximum Dots ALPR Surveillance Network",
        "filename": "maximum_dots.csv",
        "format": "CSV",
        "source": "colonelpanichacks/flock-you",
        "source_url": "https://github.com/colonelpanichacks/flock-you/blob/main/datasets/maximum_dots.csv",
        "download_url": "https://raw.githubusercontent.com/colonelpanichacks/flock-you/main/datasets/maximum_dots.csv",
        "is_gzip": False,
        "description": "Large-scale ALPR deployment registry with camera makes, models, direction vectors, and operational status."
    },
    {
        "id": "flock_master_intercept",
        "name": "Flock Safety Master Intercept Registry",
        "filename": "Flock_Master_Registry.csv",
        "format": "CSV",
        "source": "colonelpanichacks/flock-you",
        "source_url": "https://github.com/colonelpanichacks/flock-you/blob/main/datasets/Flock-_______20240530_124303.csv",
        "download_url": "https://raw.githubusercontent.com/colonelpanichacks/flock-you/main/datasets/Flock-_______20240530_124303.csv",
        "is_gzip": False,
        "description": "Wireless telemetry intercepts of Flock cameras with SSIDs, MAC addresses, roads, cities, and regions."
    },
    {
        "id": "flock_ext_battery",
        "name": "Flock Safety Ext Battery ALPR Nodes",
        "filename": "FS_Ext_Battery.csv",
        "format": "CSV",
        "source": "colonelpanichacks/flock-you",
        "source_url": "https://github.com/colonelpanichacks/flock-you/blob/main/datasets/FS%2BExt%2BBattery_20240530_105846.csv",
        "download_url": "https://raw.githubusercontent.com/colonelpanichacks/flock-you/main/datasets/FS+Ext+Battery_20240530_105846.csv",
        "is_gzip": False,
        "description": "Flock cameras with external solar/battery installations and physical hardware telemetry."
    },
    {
        "id": "penguin_alpr_feed",
        "name": "Penguin ALPR Camera Deployment Feed",
        "filename": "Penguin_ALPR_Feed.csv",
        "format": "CSV",
        "source": "colonelpanichacks/flock-you",
        "source_url": "https://github.com/colonelpanichacks/flock-you/blob/main/datasets/Penguin-___________20240530_111436.csv",
        "download_url": "https://raw.githubusercontent.com/colonelpanichacks/flock-you/main/datasets/Penguin-___________20240530_111436.csv",
        "is_gzip": False,
        "description": "Extensive dataset of Automated License Plate Reader deployments across municipal corridors."
    }
]

def _parse_coordinates_string(val):
    """Extracts (lat, lon) tuple from composite coordinate string like '41.092545, -81.557472'."""
    if not val:
        return None, None
    s = str(val).strip().strip('"').strip("'")
    # Matches format "lat, lon" or "lat lon"
    parts = re.split(r'[,;\s]+', s)
    if len(parts) >= 2:
        try:
            lat = float(parts[0])
            lon = float(parts[1])
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                return lat, lon
        except ValueError:
            pass
    return None, None

def load_flock_file_raw_records(file_path):
    """Loads records from a Flock dataset file across CSV, JSON, GeoJSON, KML, and SQLite."""
    if not os.path.exists(file_path):
        return []

    ext = os.path.splitext(file_path)[1].lower()
    records = []

    if ext == '.geojson':
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            features = data.get('features', []) if isinstance(data, dict) else []
            for feat in features:
                props = dict(feat.get('properties', {}) or {})
                geom = feat.get('geometry', {}) or {}
                coords = geom.get('coordinates', [])
                if len(coords) >= 2:
                    props['longitude'] = coords[0]
                    props['latitude'] = coords[1]
                records.append(props)
        except Exception as e:
            print(f"Flock GeoJSON read error: {e}")

    elif ext == '.kml':
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            ns = {'kml': 'http://www.opengis.net/kml/2.2'}
            placemarks = root.findall('.//kml:Placemark', ns) or root.findall('.//Placemark')
            for pm in placemarks:
                name_node = pm.find('kml:name', ns) if 'kml' in str(root.tag) else pm.find('name')
                desc_node = pm.find('kml:description', ns) if 'kml' in str(root.tag) else pm.find('description')
                coords_node = pm.find('.//kml:coordinates', ns) if 'kml' in str(root.tag) else pm.find('.//coordinates')
                row = {
                    'name': name_node.text.strip() if name_node is not None and name_node.text else "Flock Node",
                    'description': desc_node.text.strip() if desc_node is not None and desc_node.text else ""
                }
                if coords_node is not None and coords_node.text:
                    parts = coords_node.text.strip().split(',')
                    if len(parts) >= 2:
                        try:
                            row['longitude'] = float(parts[0])
                            row['latitude'] = float(parts[1])
                        except ValueError:
                            pass
                records.append(row)
        except Exception as e:
            print(f"Flock KML read error: {e}")

    elif ext in ['.db', '.sqlite', '.sqlite3']:
        try:
            conn = sqlite3.connect(file_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [r[0] for r in cursor.fetchall()]
            if tables:
                cursor.execute(f"SELECT * FROM '{tables[0]}' LIMIT 20000;")
                records = [dict(r) for r in cursor.fetchall()]
            conn.close()
        except Exception as e:
            print(f"Flock SQLite read error: {e}")

    elif ext == '.json':
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                if data.get('type') == 'FeatureCollection' and 'features' in data:
                    for feat in data.get('features', []):
                        props = dict(feat.get('properties', {}) or {})
                        coords = feat.get('geometry', {}).get('coordinates', [])
                        if len(coords) >= 2:
                            props['longitude'] = coords[0]
                            props['latitude'] = coords[1]
                        records.append(props)
                else:
                    for k in ['cameras', 'devices', 'data', 'results', 'features', 'items']:
                        if k in data and isinstance(data[k], list):
                            records = data[k]
                            break
                    if not records:
                        records = [data]
        except Exception as e:
            print(f"Flock JSON read error: {e}")

    else:
        # Default to CSV with utf-8-sig to automatically strip UTF-8 BOM
        try:
            with open(file_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
                reader = csv.DictReader(f)
                records = list(reader)
        except Exception as e:
            print(f"Flock CSV read error: {e}")

    return records

def normalize_camera_record(row, idx, file_source=""):
    """Normalizes a raw dictionary row into a standardized tactical Camera object."""
    if not isinstance(row, dict):
        return None

    lat, lon = None, None

    # Check composite coordinates column first
    for k in ['coordinates', 'coords', 'coord', 'location', 'point']:
        if k in row and row[k]:
            clat, clon = _parse_coordinates_string(row[k])
            if clat is not None and clon is not None:
                lat, lon = clat, clon
                break

    # Check individual lat/lon columns
    if lat is None or lon is None:
        lat_candidates = ['latitude', 'lat', 'trilat', 'gps_lat', 'currentlatitude', 'lat_wgs84', 'coord_y', 'y']
        lon_candidates = ['longitude', 'lon', 'lng', 'long', 'trilong', 'gps_lon', 'currentlongitude', 'lon_wgs84', 'coord_x', 'x']

        for k in lat_candidates:
            if k in row and row[k] is not None and str(row[k]).strip() != '':
                try:
                    v = float(str(row[k]).strip())
                    if -90 <= v <= 90:
                        lat = v
                        break
                except ValueError:
                    pass

        for k in lon_candidates:
            if k in row and row[k] is not None and str(row[k]).strip() != '':
                try:
                    v = float(str(row[k]).strip())
                    if -180 <= v <= 180:
                        lon = v
                        break
                except ValueError:
                    pass

    # If coordinates couldn't be parsed, check if maps_url has embedded lat/lon
    if (lat is None or lon is None) and 'maps_url' in row and row['maps_url']:
        m = re.search(r'@(-?\d+\.\d+),(-?\d+\.\d+)', str(row['maps_url']))
        if m:
            try:
                lat = float(m.group(1))
                lon = float(m.group(2))
            except ValueError:
                pass

    if lat is None or lon is None:
        return None

    # Brand / Type identification
    brand = row.get('brand') or row.get('make') or row.get('type') or 'Flock Safety'
    if not brand or brand.lower() in ['infra', 'fixed', 'camera']:
        brand = 'Flock Safety'

    # Camera name / location
    name = (
        row.get('name') or
        row.get('info/comments') or
        row.get('note b') or
        row.get('road') or
        row.get('ssid') or
        row.get('description') or
        f"Flock Node #{idx + 1}"
    )
    if isinstance(name, str) and name.strip() == '':
        name = f"Flock ALPR Node #{idx + 1}"

    # Operator / Police Department / Agency
    operator = (
        row.get('operator') or
        row.get('agency') or
        row.get('department') or
        row.get('Country') or
        'Law Enforcement / Municipal ALPR'
    )

    # Direction (0-360 degrees or compass text)
    direction = row.get('direction') or row.get('directions') or None

    # Mount type
    mount_type = row.get('mountType') or row.get('mount_type') or row.get('config type') or 'pole'

    # Surveillance Zone
    zone = row.get('surveillanceZone') or row.get('zone') or 'traffic'

    # Notes / comments
    notes = (
        row.get('info/comments') or
        row.get('note a') or
        row.get('comment') or
        row.get('description') or
        ''
    )

    # Google Maps direct link
    maps_url = row.get('maps_url') or f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"

    # Unique Identifier
    cam_id = (
        str(row.get('osmId')) if row.get('osmId') else
        str(row.get('netid')) if row.get('netid') else
        str(row.get('note a')) if row.get('note a') else
        f"flock-{idx}-{abs(hash((lat, lon)))}"
    )

    return {
        "id": cam_id,
        "lat": round(lat, 6),
        "lon": round(lon, 6),
        "name": str(name),
        "brand": str(brand),
        "operator": str(operator),
        "direction": direction,
        "mount_type": str(mount_type),
        "zone": str(zone),
        "notes": str(notes),
        "maps_url": str(maps_url),
        "source_file": file_source
    }

def get_catalog():
    """Returns catalog list enriched with local download status, file sizes, and record counts."""
    enriched = []
    local_files = set(os.listdir(FLOCK_DIR)) if os.path.exists(FLOCK_DIR) else set()

    for item in CATALOG:
        entry = dict(item)
        fn = entry["filename"]
        fp = os.path.join(FLOCK_DIR, fn)

        if os.path.exists(fp):
            entry["is_downloaded"] = True
            entry["file_size"] = os.path.getsize(fp)
            entry["updated_at"] = int(os.path.getmtime(fp))
            # Quick count of records
            try:
                recs = load_flock_file_raw_records(fp)
                entry["camera_count"] = len(recs)
            except Exception:
                entry["camera_count"] = None
        else:
            entry["is_downloaded"] = False
            entry["file_size"] = 0
            entry["updated_at"] = None
            entry["camera_count"] = None

        enriched.append(entry)

    # Also list any custom uploaded files that are not in the predefined catalog
    catalog_filenames = {item["filename"] for item in CATALOG}
    for f in os.listdir(FLOCK_DIR):
        if f not in catalog_filenames and not f.startswith('.'):
            fp = os.path.join(FLOCK_DIR, f)
            if os.path.isfile(fp):
                ext = os.path.splitext(f)[1].lower().lstrip('.').upper() or 'CSV'
                try:
                    recs = load_flock_file_raw_records(fp)
                    cam_count = len(recs)
                except Exception:
                    cam_count = None

                parts = f.split('_', 1)
                clean_name = parts[1] if (len(parts) == 2 and parts[0].isdigit()) else f

                enriched.append({
                    "id": f"upload_{f}",
                    "name": clean_name,
                    "filename": f,
                    "format": ext,
                    "source": "User Upload",
                    "source_url": None,
                    "download_url": None,
                    "is_gzip": False,
                    "description": "User uploaded custom Flock / ALPR surveillance dataset.",
                    "is_downloaded": True,
                    "file_size": os.path.getsize(fp),
                    "updated_at": int(os.path.getmtime(fp)),
                    "camera_count": cam_count
                })

    return enriched

def _safe_dataset_path(filename):
    """Resolve a user-supplied dataset name strictly inside FLOCK_DIR.

    Dataset filenames arrive from query strings and uploads, so they are reduced
    to a basename and the resolved path is verified to stay inside the dataset
    directory.  Returns ``None`` for anything that tries to escape it.
    """
    if not filename:
        return None
    base_dir = os.path.realpath(FLOCK_DIR)
    candidate = os.path.realpath(os.path.join(base_dir, os.path.basename(str(filename))))
    if candidate == base_dir or not candidate.startswith(base_dir + os.sep):
        return None
    return candidate


def download_dataset(dataset_id):
    """Downloads a dataset from catalog or custom URL and saves it to uploads/flock/."""
    target_entry = None
    for item in CATALOG:
        if item["id"] == dataset_id or item["filename"] == dataset_id:
            target_entry = item
            break

    if not target_entry:
        return {"status": "error", "message": f"Dataset '{dataset_id}' not found in catalog"}

    url = target_entry["download_url"]
    filename = target_entry["filename"]
    save_path = _safe_dataset_path(filename)
    if save_path is None:
        return {"status": "error", "message": f"Refusing to write outside the dataset directory: {filename}"}

    try:
        resp = requests.get(url, headers={'User-Agent': 'WireTapper/1.0'}, timeout=35)
        if resp.status_code != 200:
            return {"status": "error", "message": f"Server returned HTTP {resp.status_code}"}
        raw_bytes = resp.content

        # Check if content needs gzip decompression
        if target_entry.get("is_gzip"):
            try:
                decompressed = gzip.decompress(raw_bytes)
                with open(save_path, 'wb') as f:
                    f.write(decompressed)
            except Exception:
                with open(save_path, 'wb') as f:
                    f.write(raw_bytes)
        else:
            with open(save_path, 'wb') as f:
                f.write(raw_bytes)

        # Parse to count valid cameras
        raw_recs = load_flock_file_raw_records(save_path)
        valid_cams = 0
        for i, r in enumerate(raw_recs):
            c = normalize_camera_record(r, i, filename)
            if c:
                valid_cams += 1

        return {
            "status": "success",
            "message": f"Successfully downloaded and saved {filename}",
            "filename": filename,
            "file_size": os.path.getsize(save_path),
            "camera_count": valid_cams,
            "total_records": len(raw_recs)
        }
    except Exception as e:
        print(f"Error downloading dataset {dataset_id}: {e}")
        return {"status": "error", "message": f"Download failed: {str(e)}"}

def preview_dataset(filename, page=1, per_page=40):
    """Returns preview metadata, columns, and sample normalized cameras for a dataset."""
    file_path = _safe_dataset_path(filename)
    if file_path is None or not os.path.exists(file_path):
        return {"status": "error", "message": f"File '{filename}' not found on server"}

    records = load_flock_file_raw_records(file_path)
    if not records:
        return {"status": "error", "message": "No valid records found in dataset"}

    # Extract all distinct columns
    columns = []
    seen = set()
    for r in records[:50]:
        if isinstance(r, dict):
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    columns.append(k)

    # Normalize cameras
    cameras = []
    for idx, r in enumerate(records):
        cam = normalize_camera_record(r, idx, filename)
        if cam:
            cameras.append(cam)

    total_cameras = len(cameras)
    total_records = len(records)

    # Pagination
    start = (page - 1) * per_page
    end = start + per_page
    paged_cameras = cameras[start:end]

    return {
        "status": "success",
        "filename": filename,
        "format": os.path.splitext(filename)[1].lstrip('.').upper() or 'CSV',
        "file_size": os.path.getsize(file_path),
        "total_records": total_records,
        "total_cameras": total_cameras,
        "columns": columns,
        "page": page,
        "per_page": per_page,
        "cameras": paged_cameras
    }

def search_dataset(filename, query, limit=500):
    """Searches within a Flock dataset by keyword (city, state, operator, brand, name, notes)."""
    file_path = _safe_dataset_path(filename)
    if file_path is None or not os.path.exists(file_path):
        return {"status": "error", "message": f"File '{filename}' not found"}

    records = load_flock_file_raw_records(file_path)
    q = query.lower().strip()

    matches = []
    for idx, r in enumerate(records):
        cam = normalize_camera_record(r, idx, filename)
        if not cam:
            continue

        search_blob = f"{cam['name']} {cam['brand']} {cam['operator']} {cam['notes']} {cam['mount_type']} {cam['lat']} {cam['lon']}".lower()
        if not q or q in search_blob:
            matches.append(cam)
            if len(matches) >= limit:
                break

    return {
        "status": "success",
        "filename": filename,
        "query": query,
        "match_count": len(matches),
        "cameras": matches
    }

def get_all_dataset_cameras(filename, limit=15000):
    """Extracts all normalized camera objects from a dataset file for Leaflet map display."""
    file_path = _safe_dataset_path(filename)
    if file_path is None or not os.path.exists(file_path):
        return {"status": "error", "message": f"File '{filename}' not found"}

    records = load_flock_file_raw_records(file_path)
    cameras = []
    for idx, r in enumerate(records):
        cam = normalize_camera_record(r, idx, filename)
        if cam:
            cameras.append(cam)
            if len(cameras) >= limit:
                break

    return {
        "status": "success",
        "filename": filename,
        "count": len(cameras),
        "cameras": cameras
    }

def delete_dataset(filename):
    """Deletes a downloaded dataset file from uploads/flock/."""
    safe_name = os.path.basename(filename)
    file_path = _safe_dataset_path(filename)

    if file_path is None or not os.path.exists(file_path):
        return {"status": "error", "message": f"File '{safe_name}' not found"}

    try:
        os.remove(file_path)
        return {"status": "success", "message": f"File '{safe_name}' deleted successfully"}
    except Exception as e:
        return {"status": "error", "message": f"Failed to delete file: {str(e)}"}
