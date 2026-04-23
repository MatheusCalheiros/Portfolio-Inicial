"""
vulnerable_app.py — Aplicação web propositalmente vulnerável
PROPÓSITO: demonstrar o que o Bandit (SAST) detecta.
NÃO use este código em produção.

Cada vulnerabilidade está comentada com o código Bandit que ela aciona.
"""

import subprocess
import hashlib
import os
import sqlite3
import pickle
import yaml

# ─── B601: shell injection via subprocess ────────────────────────────────────
def ping_host_vulnerable(hostname: str):
    """VULNERÁVEL: entrada do usuário direto no shell."""
    # B602: subprocess com shell=True — risco de injeção de comando
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)
    return result.stdout.decode()

def ping_host_safe(hostname: str):
    """CORRETO: lista de argumentos sem shell=True."""
    import shlex
    result = subprocess.run(["ping", "-c", "1", shlex.quote(hostname)],
                            capture_output=True, timeout=5)
    return result.stdout.decode()

# ─── B303: MD5/SHA1 para senhas ───────────────────────────────────────────────
def hash_password_vulnerable(password: str) -> str:
    """VULNERÁVEL: MD5 é criptograficamente quebrado para senhas."""
    # B303: uso de MD5 — detectado pelo Bandit
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_safe(password: str) -> str:
    """CORRETO: bcrypt ou hashlib com salt e iterações."""
    import hashlib
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + key.hex()

# ─── B608: SQL Injection ──────────────────────────────────────────────────────
def get_user_vulnerable(username: str) -> list:
    """VULNERÁVEL: concatenação de string em SQL."""
    conn = sqlite3.connect(":memory:")
    # B608: possível SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()

def get_user_safe(username: str) -> list:
    """CORRETO: parametrização da query."""
    conn = sqlite3.connect(":memory:")
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()

# ─── B301: Desserialização insegura (pickle) ──────────────────────────────────
def load_session_vulnerable(data: bytes):
    """VULNERÁVEL: pickle pode executar código arbitrário."""
    # B301: pickle.loads com dados não confiáveis
    return pickle.loads(data)

def load_session_safe(data: str) -> dict:
    """CORRETO: usar json.loads para dados não confiáveis."""
    import json
    return json.loads(data)

# ─── B506: yaml.load sem Loader ──────────────────────────────────────────────
def parse_config_vulnerable(config_str: str):
    """VULNERÁVEL: yaml.load pode executar código arbitrário."""
    # B506: yaml.load sem Loader seguro
    return yaml.load(config_str)  # noqa

def parse_config_safe(config_str: str):
    """CORRETO: yaml.safe_load."""
    return yaml.safe_load(config_str)

# ─── B105: Senha hardcoded ────────────────────────────────────────────────────
# B105: senha hardcoded detectada pelo Bandit
DATABASE_PASSWORD = "admin123"  # noqa: S105 — intencional para demonstração

# ─── B322: input() em Python 2 (histórico) ───────────────────────────────────
# Demonstração de verificação de configuração insegura de TLS
import ssl

def create_insecure_context():
    """VULNERÁVEL: desabilita verificação de certificado SSL."""
    # B501: ssl com check_hostname=False
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def create_secure_context():
    """CORRETO: contexto padrão verifica certificados."""
    return ssl.create_default_context()
