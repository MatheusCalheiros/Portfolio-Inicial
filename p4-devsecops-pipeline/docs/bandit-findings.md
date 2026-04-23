# Bandit SAST — Achados e Correções

Documentação gerada após análise estática do código com Bandit.
Cada achado explica o risco, o código vulnerável e a correção aplicada.

---

## B602 — subprocess com shell=True (HIGH)

**Arquivo:** `src/vulnerable_app.py:16`

**Código vulnerável:**
```python
subprocess.run(f"ping -c 1 {hostname}", shell=True, ...)
```

**Risco:** Se `hostname` contiver `;`, `&&`, `|` ou backticks, o atacante pode injetar comandos arbitrários.
Exemplo: `hostname = "google.com; rm -rf /"`

**Correção:**
```python
subprocess.run(["ping", "-c", "1", shlex.quote(hostname)], timeout=5)
```

---

## B303 — MD5 para hashing de senhas (MEDIUM)

**Arquivo:** `src/vulnerable_app.py:24`

**Código vulnerável:**
```python
hashlib.md5(password.encode()).hexdigest()
```

**Risco:** MD5 é criptograficamente quebrado. Tabelas rainbow e GPUs modernas quebram hashes MD5 em segundos.

**Correção:**
```python
salt = os.urandom(32)
hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310_000)
```

---

## B608 — SQL Injection via concatenação (HIGH)

**Arquivo:** `src/vulnerable_app.py:35`

**Código vulnerável:**
```python
f"SELECT * FROM users WHERE username = '{username}'"
```

**Risco:** `username = "' OR '1'='1"` retorna todos os usuários.
`username = "admin'; DROP TABLE users;--"` destrói dados.

**Correção:**
```python
conn.execute("SELECT * FROM users WHERE username = ?", (username,))
```

---

## B301 — pickle.loads com dados não confiáveis (HIGH)

**Arquivo:** `src/vulnerable_app.py:44`

**Código vulnerável:**
```python
pickle.loads(data)
```

**Risco:** Pickle pode executar código arbitrário durante a desserialização.
Um atacante que controla `data` obtém execução de código remoto (RCE).

**Correção:**
```python
json.loads(data)  # JSON não executa código
```

---

## B506 — yaml.load sem SafeLoader (MEDIUM)

**Arquivo:** `src/vulnerable_app.py:51`

**Código vulnerável:**
```python
yaml.load(config_str)
```

**Risco:** yaml.load pode instanciar objetos Python arbitrários, permitindo RCE.

**Correção:**
```python
yaml.safe_load(config_str)
```

---

## B105 — Senha hardcoded (LOW/MEDIUM)

**Arquivo:** `src/vulnerable_app.py:57`

**Código vulnerável:**
```python
DATABASE_PASSWORD = "admin123"
```

**Risco:** Senha visível em repositório público/privado. Vaza em logs, git history, etc.

**Correção:**
```python
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
if not DATABASE_PASSWORD:
    raise ValueError("DATABASE_PASSWORD não configurada")
```

---

## B501 — TLS sem verificação de certificado (HIGH)

**Arquivo:** `src/vulnerable_app.py:63`

**Código vulnerável:**
```python
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

**Risco:** Permite ataques Man-in-the-Middle. Qualquer certificado (incluindo falsos) é aceito.

**Correção:**
```python
ctx = ssl.create_default_context()  # padrão já verifica tudo
```

---

## Resumo

| Severidade | Quantidade |
|---|---|
| HIGH | 4 |
| MEDIUM | 2 |
| LOW | 1 |
| **Total** | **7** |

Todos os achados foram corrigidos em `src/secure_app.py`.
