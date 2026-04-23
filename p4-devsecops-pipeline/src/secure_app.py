"""
secure_app.py — Versão corrigida após análise SAST com Bandit.
Demonstra as boas práticas de segurança para cada padrão vulnerável.
"""

import hashlib
import json
import os
import shlex
import sqlite3
import ssl
import subprocess
import yaml
from typing import Any


def ping_host(hostname: str) -> str:
    """Executa ping sem injeção de comando."""
    result = subprocess.run(
        ["ping", "-c", "1", shlex.quote(hostname)],
        capture_output=True,
        timeout=5,
        check=False,
    )
    return result.stdout.decode(errors="replace")


def hash_password(password: str) -> str:
    """Hash seguro com PBKDF2 + salt aleatório."""
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, key_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return key.hex() == key_hex


def get_user(conn: sqlite3.Connection, username: str) -> list:
    """Query parametrizada — sem SQL injection."""
    return conn.execute(
        "SELECT id, username, email FROM users WHERE username = ?",
        (username,),
    ).fetchall()


def load_session(data: str) -> dict:
    """Desserialização segura via JSON."""
    return json.loads(data)


def parse_config(config_str: str) -> Any:
    """Parsing seguro de YAML."""
    return yaml.safe_load(config_str)


def create_tls_context() -> ssl.SSLContext:
    """Contexto TLS com verificação de certificado habilitada."""
    return ssl.create_default_context()
