import os

from pathlib import Path

# ------------------------------------------------------------------------------
# Navigation

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
GENERATED_DIR = BASE_DIR / "generated"

# ------------------------------------------------------------------------------
# Google Auth

CREDENTIALS_PATH = BASE_DIR / "credentials.json"
TOKENS_PATH = BASE_DIR / "tokens.json"

SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/gmail.send",
]

# ------------------------------------------------------------------------------
# Internal

WATCHDOC_PORT = int(os.environ["WATCHDOC_PORT"])
WATCHDOC_AUTH_PORT = int(os.environ["WATCHDOC_AUTH_PORT"])

SERVICE_EMAIL = os.environ["SERVICE_EMAIL"]

DEBUG = os.environ["DEBUG"].lower() == "true"
