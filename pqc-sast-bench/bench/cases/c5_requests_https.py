"""Fetch configuration from the control plane over HTTPS (TLS handled inside requests/urllib3)."""
import requests

def fetch_config(url: str) -> dict:
    return requests.get(url, timeout=10).json()
