"""Loads deployment configuration from files and the process environment."""
import configparser
import json
import os
import tomllib
import xml.etree.ElementTree as ElementTree
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parent
CONFIG = BASE / "config"


def _load_dotenv(path: Path = BASE / ".env") -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            os.environ.setdefault(name.strip(), value.strip())


def load() -> dict:
    _load_dotenv()
    cfg = {}
    cfg["aead"] = json.loads((CONFIG / "crypto.json").read_text())["data_protection"]["aead"]
    cfg["signing"] = yaml.safe_load((CONFIG / "signing.yaml").read_text())["signing"]
    cfg["kdf"] = dict(ElementTree.parse(CONFIG / "kdf.xml").getroot().find("kdf").attrib)
    cfg["transport"] = tomllib.loads((CONFIG / "transport.toml").read_text())["key_transport"]
    ini = configparser.ConfigParser()
    ini.read(CONFIG / "mac.ini")
    cfg["mac"] = dict(ini["mac"])
    cfg["digest"] = os.environ.get("APP_DIGEST", "SHA224")  # GT:H6-06/def
    cfg["kem"] = os.environ.get("APP_KEM")  # GT:H6-07/src
    cfg["kex"] = os.environ.get("APP_KEX")  # GT:H6-08/src
    cfg["session_cipher"] = os.environ.get("APP_SESSION_CIPHER")  # GT:H6-09/src
    return cfg
