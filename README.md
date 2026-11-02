# 📡 WireTapper

<p align="center">
  <img src="https://raw.githubusercontent.com/h9zdev/WireTapper/main/images/WireTapper.png" alt="WireTapper" />
</p>

> [!NOTE]
> **Wireless OSINT & Signal Intelligence Platform** — soon we will integrate AI in it.

WireTapper is a wireless OSINT tool designed to discover, map, and analyze radio-based devices using passive signal intelligence. It provides investigators, researchers, and security analysts with real-time visibility into the invisible wireless landscape around them.

WireTapper detects and correlates signals from common wireless technologies, helping users understand what devices exist, where they are likely located, and how they interact, without active intrusion.

WireTapper identifies leaked Wi-Fi network credentials based on a privacy-protecting k-Anonymity query scheme.

<p align="center">
  🔗 <strong>Website:</strong>
  <a href="https://haybnz.web.app?utm_source=github.com">https://haybnz.web.app</a>
</p>

<p align="center">
  📖 <strong>Wiki (Installation & Setup):</strong>
  <a href="https://github.com/h9zdev/WireTapper/wiki">github.com/h9zdev/WireTapper/wiki</a>
</p>

<p align="center">
  🔗 <strong>Blog on WireTapper:</strong>
  <a href="https://medium.com/@h9z/wire-tapper-wireless-osint-signal-intelligence-platform-e5104659a1cb?utm_source=github.com">
    Read on Medium
  </a>
</p>

<p align="center">
  <a href="https://github.com/sponsors/h9zdev">
    <img src="https://img.shields.io/badge/Make%20a%20Difference-Sponser%20My%20Work-6A1B9A?style=for-the-badge&logo=github&logoColor=white" alt="Support My Work" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/h9zdev/WireTapper">
    <img src="https://img.shields.io/static/v1?label=Python&message=WireTapper&color=2A3E87&labelColor=6A7DA8&style=for-the-badge&logo=python&logoColor=white" />
  </a>
  <a href="https://pypi.org/project/wiretapper/">
    <img src="https://img.shields.io/pypi/v/wiretapper?style=for-the-badge&color=006DAD&labelColor=3776AB&logo=pypi&logoColor=white&label=PyPI" />
  </a>
  <a href="https://github.com/h9zdev/WireTapper/issues">
    <img src="https://img.shields.io/github/issues/h9zdev/WireTapper?style=for-the-badge&color=8B0000&logo=github" />
  </a>
  <a href="https://github.com/h9zdev/WireTapper/network/members">
    <img src="https://img.shields.io/github/forks/h9zdev/WireTapper?style=for-the-badge&color=455A64&logo=github" />
  </a>
  <a href="https://github.com/h9zdev/WireTapper/stargazers">
    <img src="https://img.shields.io/github/stars/h9zdev/WireTapper?style=for-the-badge&color=FFD700&logo=github" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/h9zdev/WireTapper/releases/download/WireTapper/WireTapper-Linux">
    <img src="https://img.shields.io/static/v1?label=Platform&message=Linux&color=E95420&labelColor=333333&style=for-the-badge&logo=linux&logoColor=white" />
  </a>
  <a href="https://github.com/h9zdev/WireTapper/releases/download/WireTapper/WireTapper-macOS">
    <img src="https://img.shields.io/static/v1?label=Platform&message=macOS&color=000000&labelColor=999999&style=for-the-badge&logo=apple&logoColor=white" />
  </a>
  <a href="https://github.com/h9zdev/WireTapper/releases/download/WireTapper/WireTapper-Windows.exe">
    <img src="https://img.shields.io/static/v1?label=Platform&message=Windows&color=0078D6&labelColor=00539C&style=for-the-badge&logo=windows&logoColor=white" />
  </a>
  <a href="https://pypi.org/project/wiretapper/">
    <img src="https://img.shields.io/static/v1?label=Install&message=pip%20install%20wiretapper&color=3776AB&labelColor=FFD43B&style=for-the-badge&logo=python&logoColor=white" />
  </a>
</p>



> [!NOTE]
> ## 🛰️ SocioSential — Social Media OSINT
> [![GitHub](https://img.shields.io/badge/GitHub-h9zdev%2FSocioSential-blue?logo=github&style=flat-square)](https://github.com/h9zdev/SocioSential)
>
> ## 📡 EthiFi — WiFi Deauther *(New Version)*
> [![GitHub](https://img.shields.io/badge/GitHub-h9zdev%2FEthiFi-green?logo=github&style=flat-square)](https://github.com/h9zdev/EthiFi)



## 📶 Supported Signal Intelligence & Modules

WireTapper can identify and analyze signals from:

*   **Wi-Fi Intelligence**: Detect and map Wi-Fi networks and access points, monitor Wi-Fi activity, and analyze available Wi-Fi metadata and signal information.
*   **Bluetooth LE & RPA Radar (`/btscan`)**: Live passive BLE device detection, RSSI path-loss distance estimation, and Resolvable Private Address (RPA) resolution using AES-128-ECB `ah()` cryptographic functions.
*   **Flock Safety & ALPR Surveillance Intelligence**: Dedicated management, download, and mapping module for Automated License Plate Reader (ALPR) camera networks and telemetry datasets.
*   **Multi-Format Telemetry Importer**: Drag-and-drop ingestion and smart column-mapping for custom field reports in CSV, KML, GeoJSON, SQLite (`.db`), and Excel formats.
*   **IoT & SCADA Infrastructure Reconnaissance**: Real-time geolocation scanning for exposed cameras, IoT nodes, and industrial control systems via Shodan & Censys Search API v2.
*   **USB SDR Receiver Detection**: Hardware link detection for attached Software Defined Radio dongles (RTL-SDR, HackRF One, Airspy) with their tuning range. Detection only — WireTapper performs no RF capture, so SDR mode reports the receiver and never invents signals.
*   **Cellular Infrastructure**: Cell tower location and beacon analysis using WiGLE and OpenCellID databases.
*   **Vehicles & Consumer Devices**: RF signals from smart vehicles, dashcams, IP cameras, wearables, and IoT appliances.




## 💬 Chat & CLI mode (coordinates in, text out — no browser needed)

The whole intelligence core lives in `sigint.py` and can be driven from a
terminal. Everything starts from coordinates.

```bash
pip install -e .            # or just: python3 cli.py <command>
wiretaper chat              # interactive, coordinate-driven REPL
```

Inside chat mode (`wt>` prompt):

| You type | What happens |
| --- | --- |
| `47.2066 27.7950 2km` | scan every configured source around that point |
| `wifi 47.2066 27.7950` | Wi-Fi only · same for `bt`, `cell`, `iot`, `flock`, `sdr`, `all` |
| `where 47.2066 27.7950` | reverse-geocode — what place is this? |
| `find Ungheni` | geocode a place, then re-use it with `last` |
| `last` | re-scan the previous coordinates |
| `ask wifi near 41.0925 -81.5575 within 1km` | free text — the local analyst reads the coordinates, radius and wanted sources out of it (any unrecognised line is treated the same way) |
| `radius 500m` · `mode flock` · `limit 50` · `json on` | session defaults |
| `config` · `set SHODAN_API_KEY …` · `test` | credentials (always masked) + connectivity self-test |
| `alpr <place> [state]` | road/ALPR cameras for a place — `alpr Palm Beach Florida` |
| `export <file.csv\|.geojson>` | write the last result set to a file |
| `datasets` · `download <id>` · `import <file>` | local ALPR datasets · fetch a catalog dataset · telemetry ingestion |

One-shot subcommands for scripting:

```bash
wiretaper scan   --lat 47.2066 --lon 27.7950 --radius 2km --mode all --json
wiretaper flock  --lat 41.0925 --lon -81.5575 --radius 3km
wiretaper flock  --place "Palm Beach Florida"                       # by place name
wiretaper flock  --region FL --bbox 26.24,-80.90,27.05,-79.98 --zip-prefix 334 \
                 --export exports/palm_beach_alpr.csv               # county-wide + export
wiretaper flock-download deflock_us_master                          # fetch a catalog dataset
wiretaper where  --lat 47.2066 --lon 27.7950
wiretaper find   Ungheni Moldova
wiretaper sdr
wiretaper import uploads/flock/Flock_Master_Registry.csv
wiretaper config SHODAN_API_KEY=xxxx
wiretaper selftest
wiretaper serve            # the original web UI on :8080
```

Coordinates are accepted as decimal degrees (`47.2066 27.7950`,
`47.2066,27.7950`, `47.2066N 27.7950E`) or degrees-minutes
(`47°12.4'N 27°47.7'E`), with a radius in `m`/`km`/`mi`/`nm` (or `м`/`км`).
Results are always sorted by distance from the point you gave, and every answer
lists which sources replied and which stayed silent (no key / unreachable /
empty) — nothing is ever padded with synthetic devices.

The same analyst answers the in-app chat panel (`POST /chatgpt`); it is a
deterministic local engine, not an external LLM call.

ALPR queries accept four filters that combine freely: `--query` (free text over
city/road/SSID/MAC/notes), `--region` (`FL` or `Florida`), `--bbox`
(`south,west,north,east`) and `--zip-prefix` (`334` = Palm Beach County). A
bounding box alone also catches neighbouring counties and many rows carry no
city, so the postal prefix is what pins a county down; `--city` narrows further.
`--export` writes the result set as `.csv` or `.geojson`.

The same query is available over HTTP, so it can be opened as a direct link or
piped into another tool:

```
GET /api/flock/query?region=FL&bbox=26.24,-80.90,27.05,-79.98&zip=334
    [&format=json|geojson|csv] [&q=<text>] [&city=<name>] [&lat=&lon=&radius=]
```

A malformed `bbox` returns `400` with the reason; a valid query with no matches
returns `200` and `{"status": "empty", "devices": []}`.

## 🧪 Development

```bash
pip install -r WireTapper.txt pytest
python -m pytest        # offline suite: sigint core, CLI/chat parser and Flask routes
```

# 🚀 Installation & Configuration

Welcome to the WireTapper installation and configuration guide.

## 📦 Installation

Choose the installation method for your operating system:

- 🐧 [Linux Installation Guide](https://github.com/h9zdev/WireTapper/wiki/%F0%9F%90%A7-Linux-Installation-Guide)
- 🍎 [macOS Installation Guide](https://github.com/h9zdev/WireTapper/wiki/%F0%9F%8D%8E-macOS-Installation-Guide)
- 🪟 [Windows Installation Guide](https://github.com/h9zdev/WireTapper/wiki/%F0%9F%AA%9F-Installtion--on-Windows)
- 🐍 [Installation via PyPI](https://github.com/h9zdev/WireTapper/wiki/%F0%9F%90%8D-Installation-via-PyPI)
- 🤖 [Installation via (Android)](https://github.com/h9zdev/WireTapper/wiki/%F0%9F%A4%96-Installation-on-Android-(Termux))

## ⚙️ Configuration

After installing WireTapper, configure the required settings according to the platform-specific guide.

## 🐍 Install from PyPI

```bash
pip install wiretapper
```


## 🔑 API Services

Copy `.env.example` to `.env` (git-ignored) and fill in the keys you have, or set
them at runtime — `wiretaper config KEY=VALUE`, `set KEY VALUE` in chat mode, or
the Settings panel in the web UI. All three write to the same local
`credentials.db`; lookup order is `credentials.db` → `.env` → environment. A key
left at its `your_…` placeholder counts as *not configured*, and that source is
reported as skipped instead of being called. `wiretaper selftest` shows both.

WireTapper integrates with several external intelligence services. Configure API credentials for enhanced discovery capabilities:

*   **[Wigle.net](https://wigle.net/)** – Wireless network and Bluetooth mapping and discovery (`WIGLE_API_NAME`, `WIGLE_API_TOKEN`).
*   **[OpenCellID](https://opencellid.org/)** – Open-source global database of cell towers (`OPENCELLID_API_KEY`).
*   **[Shodan](https://www.shodan.io/)** – Search engine for Internet-connected IoT and industrial devices (`SHODAN_API_KEY`).
*   **[Censys](https://censys.io/)** – Internet host and service search API v2 (`CENSYS_API_ID`, `CENSYS_API_SECRET`).
*   **[wpa-sec](https://wpa-sec.stanev.org)** – Distributed WPA-PSK auditor database integration.

> 📖 For full installation, configuration, and setup instructions, see the **[WireTapper Wiki](https://github.com/h9zdev/WireTapper/wiki)**.



## 📷 Screenshots

![WireTapper Screenshot 1](https://github.com/h9zdev/WireTapper/blob/main/images/w0.png)
![WireTapper Screenshot 2](https://github.com/h9zdev/WireTapper/blob/main/images/w1.png)
![WireTapper Screenshot 3](https://github.com/h9zdev/WireTapper/blob/main/images/w2.png)
![WireTapper Screenshot 4](https://github.com/h9zdev/WireTapper/blob/main/images/w3.png)
![WireTapper Screenshot 5](https://github.com/h9zdev/WireTapper/blob/main/images/w4.png)
![WireTapper Screenshot 5](https://github.com/h9zdev/WireTapper/blob/main/images/w5.png)



## 📜 License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) License. See the [LICENSE](LICENSE) file for more details.

**Unauthorized use is strictly prohibited.**

📧 Contact: singularat@protn.me


## ☕ Support

Donate via Monero: `45PU6txuLxtFFcVP95qT2xXdg7eZzPsqFfbtZp5HTjLbPquDAugBKNSh1bJ76qmAWNGMBCKk4R1UCYqXxYwYfP2wTggZNhq`



## 👥 Contributors and Developers

[<img src="https://avatars.githubusercontent.com/u/67865621?s=64&v=4" width="64" height="64" alt="haybnzz">](https://github.com/h9zdev)
[<img src="https://avatars.githubusercontent.com/u/108749445?s=64&v=4"  width="64" height="64" alt="VaradScript">](https://github.com/varadScript)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=h9zdev/WireTapper&type=timeline&legend=bottom-right)](https://www.star-history.com/#h9zdev/WireTapper&type=timeline&legend=bottom-right)
