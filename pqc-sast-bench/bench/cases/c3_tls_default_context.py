"""Telemetry uplink over TLS using the platform default context."""
import socket
import ssl

def open_uplink(host: str, port: int = 443):
    context = ssl.create_default_context()
    raw = socket.create_connection((host, port))
    return context.wrap_socket(raw, server_hostname=host)
