from setuptools import setup

with open("WireTapper.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="wiretaper",
    version="1.1.0",
    description="Wireless OSINT & Signal Intelligence Platform",
    author="WireTapper Developer",
    py_modules=["app", "cli", "sigint", "telemetry_importer", "flock_manager"],
    include_package_data=True,
    package_data={
        "": ["templates/*", "templates/*/*", "static/*", "static/*/*", "uploads/*", "uploads/*/*"],
    },
    install_requires=requirements,
    extras_require={
        "telemetry": ["pandas", "openpyxl"],
        "bluetooth": ["bleak"],
        "dev": ["pytest"],
    },
    entry_points={
        "console_scripts": [
            "wiretapper = cli:main",
        ],
    },
    python_requires=">=3.9",
)
