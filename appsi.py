from dotenv import load_dotenv
load_dotenv()

import os
import json
import time
import sqlite3
import logging
import sys
import threading
import hashlib
import signal
import re
import secrets
import uuid
from urllib.parse import urlparse
from datetime import datetime, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler

import jwt 
import pyodbc
import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, request, jsonify, g
from werkzeug.middleware.proxy_fix import ProxyFix
from waitress import serve

# Enable pyodbc connection pooling
pyodbc.pooling = True

# =========================================================
# CONFIGURACIÓN CIFRADA
# =========================================================
def cargar_configuracion():
    key = os.getenv("APP_CONFIG_KEY")
    if not key:
        raise ValueError("Falta APP_CONFIG_KEY")

    key = key.strip()

    config_path = os.getenv("APP_CONFIG_PATH", "config.enc")

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"No existe: {config_path}")

    with open(config_path, "rb") as f:
        encrypted_data = f.read()

    try:
        fernet = Fernet(key.encode())
        decrypted_data = fernet.decrypt(encrypted_data)
    except InvalidToken:
        raise ValueError("❌ ERROR: APP_CONFIG_KEY incorrecta o config.enc corrupto")

    return json.loads(decrypted_data.decode())

CONFIG = cargar_configuracion()

# =========================================================
# ENV
# =========================================================
def parse_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value != 0
    value = str(value).strip().lower()
    if value in ("1", "true", "yes", "si", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    return default

def parse_yes_no_config(value, default="yes"):
    if value is None:
        return default
    value = str(value).strip().lower()
    if value in ("yes", "no"):
        return value
    if value in ("1", "true", "on", "si"):
        return "yes"
    if value in ("0", "false", "off"):
        return "no"
    return default


JWT_SECRET = os.getenv("JWT_SECRET")
APP_USER = os.getenv("APP_USER")
APP_PASSWORD = os.getenv("APP_PASSWORD")
APP_PASSWORD_HASH = os.getenv("APP_PASSWORD_HASH")
AUTH_SALT = os.getenv("AUTH_SALT", "")
TRUST_PROXY_HEADERS = parse_bool(os.getenv("TRUST_PROXY_HEADERS", "false"), False)
TRUSTED_PROXY_COUNT = max(0, int(os.getenv("TRUSTED_PROXY_COUNT", "1") or "1"))
ALLOW_INSECURE_PUI_URL = parse_bool(os.getenv("ALLOW_INSECURE_PUI_URL", "false"), False)
HEALTH_REQUIRE_TOKEN = parse_bool(os.getenv("HEALTH_REQUIRE_TOKEN", "false"), False)

if not JWT_SECRET:
    raise ValueError("Falta JWT_SECRET")

if len(JWT_SECRET) < 32:
    raise ValueError("JWT_SECRET debe tener al menos 32 caracteres")

if not APP_USER or (not APP_PASSWORD and not APP_PASSWORD_HASH):
    raise ValueError("Faltan credenciales APP_USER / APP_PASSWORD o APP_PASSWORD_HASH")

if APP_PASSWORD_HASH and not AUTH_SALT:
    raise ValueError("AUTH_SALT es obligatorio cuando se usa APP_PASSWORD_HASH")

USUARIOS = {
    APP_USER: APP_PASSWORD_HASH or APP_PASSWORD
}

# =========================================================
# CONFIG GENERAL
# =========================================================
PORT = int(CONFIG.get("PORT", 5000))

SQL_SERVER = CONFIG["SQL_SERVER"]
SQL_DATABASE = CONFIG["SQL_DATABASE"]
SQL_USER = CONFIG["SQL_USER"]
SQL_PASSWORD = CONFIG["SQL_PASSWORD"]
SQL_DRIVER = CONFIG.get("SQL_DRIVER", "{ODBC Driver 17 for SQL Server}")
EMPRESA_ID = CONFIG["EMPRESA_ID"]

PUI_BASE_URL = CONFIG["PUI_BASE_URL"].rstrip("/")  # <-- IMPORTANTE
PUI_INSTITUCION_ID = CONFIG["PUI_INSTITUCION_ID"]
PUI_CLAVE = CONFIG["PUI_CLAVE"]

LOCAL_DB_PATH = CONFIG.get("LOCAL_DB_PATH", "pui_local.db")
REQUEST_TIMEOUT = int(CONFIG.get("REQUEST_TIMEOUT", 15))

PHASE3_INTERVAL_SECONDS = int(CONFIG.get("PHASE3_INTERVAL_SECONDS", 300))
ENABLE_PHASE3_THREAD = parse_bool(CONFIG.get("ENABLE_PHASE3_THREAD", True), True)
SQL_ENCRYPT = parse_yes_no_config(CONFIG.get("SQL_ENCRYPT", "yes"), "yes")
SQL_TRUST_SERVER_CERTIFICATE = parse_yes_no_config(CONFIG.get("SQL_TRUST_SERVER_CERTIFICATE", "no"), "no")
VERIFY_TLS = parse_bool(CONFIG.get("VERIFY_TLS", True), True)
STORE_FULL_COINCIDENCE_PAYLOADS = parse_bool(CONFIG.get("STORE_FULL_COINCIDENCE_PAYLOADS", True), True)
MAX_AUDIT_QUERY_LENGTH = 250
GENERIC_DB_ERROR_MESSAGE = "Error interno al consultar datos"
UUID_REGEX = re.compile(r"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[1-5A-Fa-f][A-Fa-f0-9]{3}-[89ABab][A-Fa-f0-9]{3}-[A-Fa-f0-9]{12}$")
SAFE_ID_REGEX = re.compile(r"^[A-Za-z0-9._:-]{36,75}$")

# CACHE TOKEN
PUI_TOKEN_CACHE = {
    "token": None,
    "exp": None
}
PUI_TOKEN_LOCK = threading.Lock()

# RATE LIMITER (simple in-memory)
LOGIN_ATTEMPTS = {}
LOGIN_ATTEMPTS_LOCK = threading.Lock()

# THREAD
PHASE3_THREAD = None
PHASE3_STOP_EVENT = threading.Event()


def _is_local_host(hostname):
    return hostname in {"localhost", "127.0.0.1", "::1"}

def validar_pui_base_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("PUI_BASE_URL debe iniciar con http:// o https://")
    if parsed.scheme != "https" and not (ALLOW_INSECURE_PUI_URL and _is_local_host(parsed.hostname or "")):
        raise ValueError("PUI_BASE_URL debe usar HTTPS en producción")
    if not parsed.netloc:
        raise ValueError("PUI_BASE_URL inválida")
    return url.rstrip("/")

PUI_BASE_URL = validar_pui_base_url(PUI_BASE_URL)

def sanitizar_valor_sensible(valor):
    if valor is None:
        return None
    if isinstance(valor, str):
        if len(valor) <= 4:
            return "***"
        return valor[:2] + "***" + valor[-2:]
    return "***"

SENSITIVE_FIELDS = {
    "curp", "nombre", "primer_apellido", "segundo_apellido", "correo", "telefono",
    "direccion", "calle", "numero", "colonia", "codigo_postal", "municipio_o_alcaldia",
    "entidad_federativa", "clave", "password", "token", "access_token", "authorization",
    "sql_password", "pwd", "jwt_secret", "app_password", "pui_clave"
}

def sanitizar_para_log(obj, max_len=1000):
    def _walk(value, parent_key=None):
        if isinstance(value, dict):
            return {k: (sanitizar_valor_sensible(v) if str(k).strip().lower() in SENSITIVE_FIELDS else _walk(v, k)) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(v, parent_key) for v in value]
        if isinstance(value, tuple):
            return tuple(_walk(v, parent_key) for v in value)
        if isinstance(value, str):
            return value if len(value) <= max_len else value[:max_len] + "... (truncated)"
        return value
    return _walk(obj)

def obtener_ip_cliente():
    return request.remote_addr or "unknown"

def verificar_credenciales(usuario, clave):
    esperado = USUARIOS.get(usuario)
    if esperado is None or not isinstance(clave, str) or len(clave) > 1024:
        return False
    recibido = clave
    if APP_PASSWORD_HASH:
        recibido = hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"), AUTH_SALT.encode("utf-8"), 600000).hex()
    return secrets.compare_digest(str(esperado), str(recibido))

def validar_fecha_iso(valor, campo):
    if valor in (None, ""):
        return None
    if not isinstance(valor, str):
        raise ValueError(f"{campo} debe ser string")
    try:
        return datetime.strptime(valor[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError as exc:
        raise ValueError(f"{campo} debe tener formato YYYY-MM-DD") from exc

def validar_correo(valor):
    if valor in (None, ""):
        return None
    valor = str(valor).strip()
    if len(valor) > 254 or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", valor):
        raise ValueError("correo inválido")
    return valor

def validar_codigo_postal(valor):
    if valor in (None, ""):
        return None
    valor = str(valor).strip()
    if not re.match(r"^\d{5}$", valor):
        raise ValueError("codigo_postal inválido")
    return valor

def limpiar_entero_positivo(valor, default_value=0, max_value=500):
    try:
        valor = int(valor)
    except (TypeError, ValueError):
        valor = default_value
    if valor < 0:
        valor = default_value
    return min(valor, max_value)

def es_uuid_valido(valor):
    return isinstance(valor, str) and UUID_REGEX.match(valor.strip()) is not None

def limitar_texto(valor, max_len=255, field_name="valor"):
    valor = valor_o_none(valor)
    if valor is None:
        return None
    if len(valor) > max_len:
        raise ValueError(f"{field_name} excede longitud permitida")
    return valor

def construir_resumen_sql_para_auditoria(query, params):
    query_limpia = " ".join(str(query).split())
    if len(query_limpia) > MAX_AUDIT_QUERY_LENGTH:
        query_limpia = query_limpia[:MAX_AUDIT_QUERY_LENGTH] + "... (truncated)"
    return {
        "query_preview": query_limpia,
        "param_count": len(params or []),
    }


def minimizar_payload_para_almacenamiento(payload, respuesta_pui=None):
    payload_guardado = payload if STORE_FULL_COINCIDENCE_PAYLOADS else sanitizar_para_log(payload)
    respuesta_guardada = respuesta_pui
    if respuesta_pui is not None and not STORE_FULL_COINCIDENCE_PAYLOADS:
        if isinstance(respuesta_pui, dict):
            respuesta_guardada = {"status_code": respuesta_pui.get("status_code")}
        else:
            respuesta_guardada = {"status_code": None}
    return payload_guardado, respuesta_guardada

def require_json_request():
    if request.method in ("POST", "PUT", "PATCH") and not request.is_json:
        return jsonify({"error": "Content-Type debe ser application/json"}), 415
    return None

def validar_campos_reporte(data):
    reporte = {
        "id": data["id"],
        "curp": data["curp"],
        "nombre": limitar_texto(data.get("nombre"), 255, "nombre"),
        "primer_apellido": limitar_texto(data.get("primer_apellido"), 255, "primer_apellido"),
        "segundo_apellido": limitar_texto(data.get("segundo_apellido"), 255, "segundo_apellido"),
        "fecha_nacimiento": validar_fecha_iso(valor_o_none(data.get("fecha_nacimiento")), "fecha_nacimiento"),
        "fecha_desaparicion": validar_fecha_iso(valor_o_none(data.get("fecha_desaparicion")), "fecha_desaparicion"),
        "lugar_nacimiento": limitar_texto(valor_o_none(data.get("lugar_nacimiento")) or lugar_nacimiento_desde_curp(data["curp"]), 255, "lugar_nacimiento"),
        "sexo_asignado": limitar_texto(data.get("sexo_asignado"), 10, "sexo_asignado"),
        "telefono": limitar_texto(data.get("telefono"), 25, "telefono"),
        "correo": validar_correo(valor_o_none(data.get("correo"))),
        "direccion": limitar_texto(data.get("direccion"), 255, "direccion"),
        "calle": limitar_texto(data.get("calle"), 255, "calle"),
        "numero": limitar_texto(data.get("numero"), 50, "numero"),
        "colonia": limitar_texto(data.get("colonia"), 255, "colonia"),
        "codigo_postal": validar_codigo_postal(valor_o_none(data.get("codigo_postal"))),
        "municipio_o_alcaldia": limitar_texto(data.get("municipio_o_alcaldia"), 255, "municipio_o_alcaldia"),
        "entidad_federativa": limitar_texto(data.get("entidad_federativa"), 255, "entidad_federativa"),
    }
    if reporte["sexo_asignado"]:
        sexo = normalizar_texto(reporte["sexo_asignado"])
        if sexo not in ("H", "M", "X"):
            raise ValueError("sexo_asignado inválido")
        reporte["sexo_asignado"] = sexo
    if reporte["telefono"]:
        telefono = re.sub(r"\s+", "", reporte["telefono"])
        if not re.match(r"^[+0-9()\-\s]{7,25}$", reporte["telefono"]):
            raise ValueError("telefono inválido")
        reporte["telefono"] = telefono
    return reporte

# =========================================================
# LOGGING
# =========================================================
logger = logging.getLogger("app")
logger.setLevel(logging.INFO)

if not logger.handlers:
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = RotatingFileHandler("app.log", maxBytes=10*1024*1024, backupCount=5)
    fh.setFormatter(formatter)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

# Signal handling for graceful shutdown
def signal_handler(signum, frame):
    logger.info(f"Recibida señal {signum}, iniciando shutdown limpio...")
    PHASE3_STOP_EVENT.set()
    if PHASE3_THREAD and PHASE3_THREAD.is_alive():
        PHASE3_THREAD.join(timeout=5)
    logger.info("Shutdown limpio completado")
    sys.exit(0)

# Register signal handlers (works on Unix and Windows)
try:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
except (AttributeError, ValueError):
    # Windows may not support all signals, fallback to atexit
    import atexit
    atexit.register(lambda: (PHASE3_STOP_EVENT.set(), logger.info("Shutdown via atexit")))

# =========================================================
# FLASK
# =========================================================
app = Flask(__name__)
if TRUST_PROXY_HEADERS and TRUSTED_PROXY_COUNT > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_COUNT, x_proto=TRUSTED_PROXY_COUNT, x_host=TRUSTED_PROXY_COUNT)
# Limit request size to 1MB to prevent oversized payloads
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# Security headers for OWASP ZAP compliance
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '0'
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['X-Request-ID'] = getattr(g, 'request_id', '')
    return response

# =========================================================
# MAPEO CURP -> LUGAR_NACIMIENTO
# =========================================================
# CURP Regex for stronger validation
CURP_REGEX = r'^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$'

CURP_ESTADOS = {
    "AS": "AGUASCALIENTES",
    "BC": "BAJA CALIFORNIA",
    "BS": "BAJA CALIFORNIA SUR",
    "CC": "CAMPECHE",
    "CS": "CHIAPAS",
    "CH": "CHIHUAHUA",
    "DF": "CDMX",
    "CL": "COAHUILA",
    "CM": "COLIMA",
    "DG": "DURANGO",
    "GT": "GUANAJUATO",
    "GR": "GUERRERO",
    "HG": "HIDALGO",
    "JC": "JALISCO",
    "MC": "MÉXICO",
    "MN": "MICHOACÁN",
    "MS": "MORELOS",
    "NT": "NAYARIT",
    "NL": "NUEVO LEÓN",
    "OC": "OAXACA",
    "PL": "PUEBLA",
    "QO": "QUERÉTARO",
    "QR": "QUINTANA ROO",
    "SP": "SAN LUIS POTOSÍ",
    "SL": "SINALOA",
    "SR": "SONORA",
    "TC": "TABASCO",
    "TS": "TAMAULIPAS",
    "TL": "TLAXCALA",
    "VZ": "VERACRUZ",
    "YN": "YUCATÁN",
    "ZS": "ZACATECAS",
    "NE": "FORÁNEO",
    "XX": "DESCONOCIDO",
}

# =========================================================
# SQLITE LOCAL
# =========================================================
def asegurar_permisos_archivo_local():
    try:
        db_path = os.path.abspath(LOCAL_DB_PATH)
        if os.path.exists(db_path) and os.name != "nt":
            os.chmod(db_path, 0o600)
    except Exception as e:
        logger.warning(f"No fue posible ajustar permisos del archivo local: {e}")

def obtener_conexion_local():
    conn = sqlite3.connect(LOCAL_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for better concurrency and reduced blocking
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    # Set busy_timeout to prevent database locked errors (5000ms = 5 seconds)
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def inicializar_db_local():
    with obtener_conexion_local() as conn:
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS reportes (
            id TEXT PRIMARY KEY,
            curp TEXT,
            nombre TEXT,
            primer_apellido TEXT,
            segundo_apellido TEXT,
            fecha_nacimiento TEXT,
            fecha_desaparicion TEXT,
            lugar_nacimiento TEXT,
            sexo_asignado TEXT,
            telefono TEXT,
            correo TEXT,
            direccion TEXT,
            calle TEXT,
            numero TEXT,
            colonia TEXT,
            codigo_postal TEXT,
            municipio_o_alcaldia TEXT,
            entidad_federativa TEXT,
            estatus TEXT,
            fase_actual TEXT,
            usuario_receptor TEXT,
            fecha_recepcion TEXT,
            fecha_actualizacion TEXT,
            ultimo_corte_fase3 TEXT,
            activa_fase3 INTEGER DEFAULT 0,
            procesando_fase3 INTEGER DEFAULT 0,
            procesando_fase3_timestamp TEXT
        )
        """)

        # Add procesando_fase3 column if it doesn't exist (for existing databases)
        try:
            cur.execute("ALTER TABLE reportes ADD COLUMN procesando_fase3 INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            # Column already exists, ignore
            pass

        # Add procesando_fase3_timestamp column if it doesn't exist (for existing databases)
        try:
            cur.execute("ALTER TABLE reportes ADD COLUMN procesando_fase3_timestamp TEXT")
        except sqlite3.OperationalError:
            # Column already exists, ignore
            pass

        cur.execute("""
        CREATE TABLE IF NOT EXISTS coincidencias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporte_id TEXT,
            fase_busqueda TEXT,
            payload_json TEXT,
            respuesta_pui_json TEXT,
            fecha_envio TEXT,
            hash_unico TEXT
        )
        """)

        cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_coincidencias_hash
        ON coincidencias(hash_unico)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evento TEXT,
            referencia_id TEXT,
            detalle TEXT,
            fecha_evento TEXT
        )
        """)

        # Create indexes for performance
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reportes_estatus ON reportes(estatus)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reportes_fase3 ON reportes(activa_fase3, procesando_fase3)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_coincidencias_reporte ON coincidencias(reporte_id)")

        conn.commit()
    asegurar_permisos_archivo_local()


def guardar_reporte_local(data, usuario_receptor, estatus, fase_actual=None):
    with obtener_conexion_local() as conn:
        conn.execute(
            """
            INSERT INTO reportes (
                id, curp, nombre, primer_apellido, segundo_apellido,
                fecha_nacimiento, fecha_desaparicion, lugar_nacimiento,
                sexo_asignado, telefono, correo, direccion, calle, numero, colonia,
                codigo_postal, municipio_o_alcaldia, entidad_federativa,
                estatus, fase_actual, usuario_receptor, fecha_recepcion,
                fecha_actualizacion, ultimo_corte_fase3, activa_fase3
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(id) DO UPDATE SET
                curp=excluded.curp,
                nombre=excluded.nombre,
                primer_apellido=excluded.primer_apellido,
                segundo_apellido=excluded.segundo_apellido,
                fecha_nacimiento=excluded.fecha_nacimiento,
                fecha_desaparicion=excluded.fecha_desaparicion,
                lugar_nacimiento=excluded.lugar_nacimiento,
                sexo_asignado=excluded.sexo_asignado,
                telefono=excluded.telefono,
                correo=excluded.correo,
                direccion=excluded.direccion,
                calle=excluded.calle,
                numero=excluded.numero,
                colonia=excluded.colonia,
                codigo_postal=excluded.codigo_postal,
                municipio_o_alcaldia=excluded.municipio_o_alcaldia,
                entidad_federativa=excluded.entidad_federativa,
                estatus=excluded.estatus,
                fase_actual=excluded.fase_actual,
                usuario_receptor=excluded.usuario_receptor,
                fecha_actualizacion=excluded.fecha_actualizacion,
                ultimo_corte_fase3=excluded.ultimo_corte_fase3
            """,
            (
                data["id"],
                data.get("curp"),
                data.get("nombre"),
                data.get("primer_apellido"),
                data.get("segundo_apellido"),
                data.get("fecha_nacimiento"),
                data.get("fecha_desaparicion"),
                data.get("lugar_nacimiento"),
                data.get("sexo_asignado"),
                data.get("telefono"),
                data.get("correo"),
                data.get("direccion"),
                data.get("calle"),
                data.get("numero"),
                data.get("colonia"),
                data.get("codigo_postal"),
                data.get("municipio_o_alcaldia"),
                data.get("entidad_federativa"),
                estatus,
                fase_actual,
                usuario_receptor,
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
            )
        )
        conn.commit()


def actualizar_estatus_reporte_local(reporte_id, estatus, fase_actual=None):
    with obtener_conexion_local() as conn:
        conn.execute(
            """
            UPDATE reportes
            SET estatus = ?, fase_actual = ?, fecha_actualizacion = ?
            WHERE id = ?
            """,
            (estatus, fase_actual, datetime.utcnow().isoformat(), reporte_id)
        )
        conn.commit()


def actualizar_corte_fase3(reporte_id, nuevo_corte):
    with obtener_conexion_local() as conn:
        conn.execute(
            """
            UPDATE reportes
            SET ultimo_corte_fase3 = ?, fecha_actualizacion = ?
            WHERE id = ?
            """,
            (nuevo_corte, datetime.utcnow().isoformat(), reporte_id)
        )
        conn.commit()


def desactivar_fase3_local(reporte_id):
    with obtener_conexion_local() as conn:
        conn.execute(
            """
            UPDATE reportes
            SET activa_fase3 = 0,
                estatus = 'DESACTIVADO',
                fecha_actualizacion = ?
            WHERE id = ?
            """,
            (datetime.utcnow().isoformat(), reporte_id)
        )
        conn.commit()


def marcar_procesando_fase3(reporte_id):
    with obtener_conexion_local() as conn:
        cursor = conn.execute(
            """
            UPDATE reportes
            SET procesando_fase3 = 1,
                procesando_fase3_timestamp = ?,
                fecha_actualizacion = ?
            WHERE id = ? AND procesando_fase3 = 0
            """,
            (datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), reporte_id)
        )
        conn.commit()
        return cursor.rowcount > 0


def desmarcar_procesando_fase3(reporte_id):
    with obtener_conexion_local() as conn:
        conn.execute(
            """
            UPDATE reportes
            SET procesando_fase3 = 0,
                procesando_fase3_timestamp = NULL,
                fecha_actualizacion = ?
            WHERE id = ?
            """,
            (datetime.utcnow().isoformat(), reporte_id)
        )
        conn.commit()


def guardar_coincidencia_local(reporte_id, fase_busqueda, payload, respuesta_pui, hash_unico):
    payload_guardado, respuesta_guardada = minimizar_payload_para_almacenamiento(payload, respuesta_pui)
    with obtener_conexion_local() as conn:
        conn.execute(
            """
            INSERT INTO coincidencias (reporte_id, fase_busqueda, payload_json, respuesta_pui_json, fecha_envio, hash_unico)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                reporte_id,
                fase_busqueda,
                json.dumps(payload_guardado, ensure_ascii=False),
                json.dumps(respuesta_guardada, ensure_ascii=False),
                datetime.utcnow().isoformat(),
                hash_unico
            )
        )
        conn.commit()


def existe_coincidencia_hash(hash_unico):
    with obtener_conexion_local() as conn:
        row = conn.execute(
            "SELECT 1 FROM coincidencias WHERE hash_unico = ? LIMIT 1",
            (hash_unico,)
        ).fetchone()
        return row is not None


def registrar_auditoria(evento, referencia_id, detalle):
    try:
        with obtener_conexion_local() as conn:
            conn.execute(
                """
                INSERT INTO auditoria (evento, referencia_id, detalle, fecha_evento)
                VALUES (?, ?, ?, ?)
                """,
                (evento, referencia_id, json.dumps(sanitizar_para_log(detalle), ensure_ascii=False) if not isinstance(detalle, str) else str(sanitizar_para_log(detalle)), datetime.utcnow().isoformat())
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Error auditoría: {e}")


def obtener_reportes_fase3_activos():
    with obtener_conexion_local() as conn:
        # Cleanup stale processing flags (timeout of 1 hour) in case worker died
        try:
            conn.execute(
                """
                UPDATE reportes
                SET procesando_fase3 = 0,
                    procesando_fase3_timestamp = NULL
                WHERE procesando_fase3 = 1
                  AND procesando_fase3_timestamp IS NOT NULL
                  AND procesando_fase3_timestamp < datetime('now', '-1 hour')
                """
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Error limpiando flags stale: {e}")
        
        rows = conn.execute(
            """
            SELECT *
            FROM reportes
            WHERE activa_fase3 = 1
              AND estatus NOT IN ('DESACTIVADO')
              AND procesando_fase3 = 0
            LIMIT 50
            """
        ).fetchall()
        return [row_to_dict(r) for r in rows]


def row_to_dict(row):
    if row is None:
        return None
    result = {}
    for k in row.keys():
        val = row[k]
        # Convert datetime objects to ISO strings for JSON serialization
        if isinstance(val, datetime):
            result[k] = val.isoformat()
        else:
            result[k] = val
    return result


def ejecutar_con_reintento(fn, retries=3):
    """Retry wrapper for SQLite writes to handle database locked errors"""
    for i in range(retries):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and i < retries - 1:
                wait_time = 0.2 * (i + 1)
                logger.warning(f"SQLite locked, retrying in {wait_time}s (attempt {i + 1}/{retries})")
                time.sleep(wait_time)
                continue
            raise


def limpiar_db_antigua():
    """Clean up old records to prevent database bloat"""
    try:
        with obtener_conexion_local() as conn:
            # Delete audit records older than 30 days
            deleted_auditoria = conn.execute(
                "DELETE FROM auditoria WHERE fecha_evento < datetime('now', '-30 days')"
            ).rowcount
            
            # Delete coincidence records older than 90 days
            deleted_coincidencias = conn.execute(
                "DELETE FROM coincidencias WHERE fecha_envio < datetime('now', '-90 days')"
            ).rowcount
            
            conn.commit()
            
            if deleted_auditoria > 0 or deleted_coincidencias > 0:
                logger.info(f"Limpieza DB: {deleted_auditoria} auditoria, {deleted_coincidencias} coincidencias eliminadas")
    except Exception as e:
        logger.error(f"Error en limpieza de DB: {e}")


def normalizar_texto(valor):
    if valor is None:
        return None
    if not isinstance(valor, str):
        valor = str(valor)
    valor = valor.strip().upper()
    return valor if valor else None


def valor_o_none(valor):
    if valor is None:
        return None
    if isinstance(valor, str):
        valor = valor.strip()
        return valor if valor else None
    return valor


def construir_nombre_completo(nombre, primer_apellido, segundo_apellido):
    partes = [valor_o_none(nombre), valor_o_none(primer_apellido), valor_o_none(segundo_apellido)]
    return " ".join([p for p in partes if p])


def formato_fecha_iso(valor):
    if valor is None:
        return None
    if isinstance(valor, datetime):
        return valor.strftime("%Y-%m-%d")
    texto = str(valor).strip()
    # Try strict parsing first
    try:
        dt = datetime.strptime(texto[:10], "%Y-%m-%d")
        return dt.strftime("%Y-%m-%d")
    except (ValueError, IndexError):
        # Fallback to string cutting if parsing fails
        if len(texto) >= 10:
            return texto[:10]
        return texto


def lugar_nacimiento_desde_curp(curp):
    curp = normalizar_texto(curp)
    if not curp or len(curp) != 18:
        return "DESCONOCIDO"
    codigo = curp[11:13]
    return CURP_ESTADOS.get(codigo, "DESCONOCIDO")


def calcular_fecha_inicio_historica(fecha_desaparicion):
    hoy = datetime.utcnow().date()
    if not fecha_desaparicion:
        return None, hoy

    try:
        f = datetime.strptime(fecha_desaparicion[:10], "%Y-%m-%d").date()
    except Exception:
        return None, hoy

    # Calculate 12 years ago correctly handling leap years
    try:
        hace_12_anios = hoy.replace(year=hoy.year - 12)
    except ValueError:
        # Handle edge case when today is Feb 29 and 12 years ago is not a leap year
        hace_12_anios = hoy.replace(year=hoy.year - 12, day=28)
    
    if f < hace_12_anios:
        f = hace_12_anios
    return f, hoy


def generar_hash_coincidencia(reporte_id, fase_busqueda, detalle):
    base = {
        "reporte_id": reporte_id,
        "fase_busqueda": fase_busqueda,
        "cliente_id": detalle.get("cliente_id"),
        "aval_id": detalle.get("aval_id"),
        "fecha_evento": detalle.get("fecha_evento"),  # Preserve raw value including milliseconds
        "curp": detalle.get("curp"),
    }
    base_str = json.dumps(base, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(base_str.encode()).hexdigest()

# =========================================================
# VALIDACIONES
# =========================================================
def validar_json(campos_obligatorios):
    if not request.is_json:
        return None, "Content-Type debe ser application/json"

    data = request.get_json(silent=True)

    if data is None:
        return None, "JSON no enviado"

    if not isinstance(data, dict):
        return None, "JSON inválido"

    for campo in campos_obligatorios:
        if campo not in data:
            return None, f"Falta campo obligatorio: {campo}"

        valor = data.get(campo)
        if valor is None or (isinstance(valor, str) and not valor.strip()):
            return None, f"Campo obligatorio vacío: {campo}"

    return data, None

def validar_curp(curp):
    if not isinstance(curp, str):
        return False, "CURP inválida"
    curp = curp.strip().upper()
    if len(curp) != 18:
        return False, "CURP debe tener 18 caracteres"
    if not re.match(CURP_REGEX, curp):
        return False, "CURP formato inválido"
    return True, curp


def validar_id_busqueda(id_busqueda):
    if not isinstance(id_busqueda, str):
        return False, "ID inválido"
    id_busqueda = id_busqueda.strip()
    if len(id_busqueda) < 36 or len(id_busqueda) > 75:
        return False, "ID debe tener entre 36 y 75 caracteres"
    if es_uuid_valido(id_busqueda):
        return True, id_busqueda
    if SAFE_ID_REGEX.match(id_busqueda):
        return True, id_busqueda
    return False, "ID contiene caracteres inválidos"

# =========================================================
# SQL SERVER
# =========================================================
def obtener_conexion_sql():
    conn_str = (
        f"DRIVER={SQL_DRIVER};"
        f"SERVER={SQL_SERVER};"
        f"DATABASE={SQL_DATABASE};"
        f"UID={SQL_USER};"
        f"PWD={SQL_PASSWORD};"
        f"Encrypt={SQL_ENCRYPT};"
        f"TrustServerCertificate={SQL_TRUST_SERVER_CERTIFICATE};"
    )
    max_retries = 3
    for intento in range(max_retries):
        try:
            return pyodbc.connect(conn_str, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            if intento == max_retries - 1:
                raise
            wait_time = 2 ** intento
            logger.warning(f"Error conectando a SQL Server (intento {intento + 1}/{max_retries}): {e}. Reintentando en {wait_time}s...")
            time.sleep(wait_time)

# =========================================================
# JWT LOCAL
# =========================================================
def generar_token_local(usuario):
    now = datetime.utcnow()
    payload = {
        "institucion_id": usuario,
        "iss": "pui-webhook",
        "aud": "pui-api",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(hours=1),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def requiere_token(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        auth = request.headers.get("Authorization")

        if not auth:
            return jsonify({"codigo": "401", "mensaje": "No hay token en header"}), 401

        if not auth.startswith("Bearer "):
            return jsonify({"codigo": "401", "mensaje": "Formato de token inválido"}), 401

        try:
            token = auth.replace("Bearer ", "", 1).strip()
            decoded = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=["HS256"],
                audience="pui-api",
                issuer="pui-webhook",
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "institucion_id"]}
            )
            g.usuario_id = decoded["institucion_id"]

            if g.usuario_id not in USUARIOS:
                return jsonify({"codigo": "403", "mensaje": "Sin permisos"}), 403

        except jwt.ExpiredSignatureError:
            return jsonify({"codigo": "401", "mensaje": "Token expirado"}), 401
        except jwt.InvalidAudienceError:
            return jsonify({"codigo": "401", "mensaje": "Audience inválido"}), 401
        except jwt.InvalidIssuerError:
            return jsonify({"codigo": "401", "mensaje": "Issuer inválido"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"codigo": "401", "mensaje": "Token inválido"}), 401
        except Exception:
            return jsonify({"codigo": "401", "mensaje": "No autorizado"}), 401

        return f(*args, **kwargs)
    return decorador

# =========================================================
# TOKEN PUI
# =========================================================
def obtener_token_pui():
    with PUI_TOKEN_LOCK:
        ahora = datetime.utcnow()

        if PUI_TOKEN_CACHE["token"] and PUI_TOKEN_CACHE["exp"] and ahora < PUI_TOKEN_CACHE["exp"]:
            return PUI_TOKEN_CACHE["token"]

        if not PUI_INSTITUCION_ID or not PUI_CLAVE:
            raise ValueError("Faltan PUI_INSTITUCION_ID o PUI_CLAVE en configuración")

        url = f"{PUI_BASE_URL.rstrip('/')}/login"
        payload = {
            "institucion_id": PUI_INSTITUCION_ID,
            "clave": PUI_CLAVE,
        }

        # Retry logic with exponential backoff
        for intento in range(3):
            try:
                r = requests.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json; charset=utf-8"},
                    timeout=(5, REQUEST_TIMEOUT),
                    verify=VERIFY_TLS,
                    allow_redirects=False
                )
                r.raise_for_status()
                
                try:
                    data = r.json()
                except Exception:
                    raise ValueError(f"Respuesta inválida de PUI: {r.text}")

                token = data.get("token") or data.get("access_token")
                if not token:
                    raise ValueError("La PUI no devolvió token")

                expires_in = int(data.get("expires_in", 3600))
                margen = max(60, int(expires_in * 0.20))
                PUI_TOKEN_CACHE["token"] = token
                PUI_TOKEN_CACHE["exp"] = ahora + timedelta(seconds=(expires_in - margen))
                return token

            except (requests.RequestException, ValueError) as e:
                if intento == 2:
                    raise
                wait_time = 2 ** intento
                logger.warning(f"Intento {intento + 1}/3 error obteniendo token PUI: {e}. Reintentando en {wait_time}s...")
                time.sleep(wait_time)

# =========================================================
# FASE 1
# =========================================================
def consultar_fase1_datos_basicos(curp, nombre=None, primer_apellido=None, segundo_apellido=None):
    curp = normalizar_texto(curp)
    nombre = normalizar_texto(nombre)
    primer_apellido = normalizar_texto(primer_apellido)
    segundo_apellido = normalizar_texto(segundo_apellido)

    query = """
    SELECT TOP 1
        cc.AvalID,
        cc.ClienteID,
        cc.RFC,
        cc.CURP,
        cc.Nombre,
        cc.ApellidoPaterno,
        cc.ApellidoMaterno,
        cc.NombreCompleto,
        cc.RazonSocial,
        cc.Correo,
        cc.FechaNacimiento,
        cc.Genero,
        cc.Calle,
        cc.NoExterior,
        cc.NoInterior,
        cc.CodigoPostal,
        cc.UltimaAct,
        cc.Fecha,
        ca.EmpresaID
    FROM CatAvales AS cc
    INNER JOIN CatClientes AS ca
        ON cc.ClienteID = ca.ClienteID
    WHERE ca.EmpresaID = ?
      AND UPPER(LTRIM(RTRIM(ISNULL(cc.CURP, '')))) = ?
    """

    params = [EMPRESA_ID, curp]

    if nombre:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.Nombre, '')))) = ?"
        params.append(nombre)

    if primer_apellido:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.ApellidoPaterno, '')))) = ?"
        params.append(primer_apellido)

    if segundo_apellido:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.ApellidoMaterno, '')))) = ?"
        params.append(segundo_apellido)

    registrar_auditoria(
        "CONSULTA_SQL_FASE1",
        curp,
        construir_resumen_sql_para_auditoria(query, params)
    )

    try:
        with obtener_conexion_sql() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            row = cursor.fetchone()

            if not row:
                return {"encontrado": False, "fase": "1", "detalle": None, "error_sql": None}

            columns = [column[0] for column in cursor.description]
            data = dict(zip(columns, row))

            detalle = {
                "aval_id": str(data.get("AvalID")) if data.get("AvalID") else None,
                "cliente_id": str(data.get("ClienteID")) if data.get("ClienteID") else None,
                "rfc": valor_o_none(data.get("RFC")),
                "curp": valor_o_none(data.get("CURP")),
                "nombre": valor_o_none(data.get("Nombre")),
                "primer_apellido": valor_o_none(data.get("ApellidoPaterno")),
                "segundo_apellido": valor_o_none(data.get("ApellidoMaterno")),
                "nombre_completo": valor_o_none(data.get("NombreCompleto")) or construir_nombre_completo(
                    data.get("Nombre"), data.get("ApellidoPaterno"), data.get("ApellidoMaterno")
                ),
                "razon_social": valor_o_none(data.get("RazonSocial")),
                "correo": valor_o_none(data.get("Correo")),
                "fecha_nacimiento": formato_fecha_iso(data.get("FechaNacimiento")),
                "sexo_asignado": valor_o_none(data.get("Genero")),
                "direccion": valor_o_none(data.get("Calle")),
                "numero": " ".join([p for p in [valor_o_none(data.get("NoExterior")), valor_o_none(data.get("NoInterior"))] if p]) or None,
                "codigo_postal": valor_o_none(data.get("CodigoPostal")),
                "empresa_id": str(data.get("EmpresaID")) if data.get("EmpresaID") else None,
                "fecha_evento": formato_fecha_iso(data.get("UltimaAct") or data.get("Fecha")),
                "descripcion_lugar_evento": "Registro institucional en CatAvales",
                "tipo_evento": "REGISTRO ADMINISTRATIVO EN CATAVALES"
            }

            return {"encontrado": True, "fase": "1", "detalle": detalle, "error_sql": None}

    except Exception as e:
        logger.error(f"Error SQL fase 1: {e}")
        return {"encontrado": False, "fase": "1", "detalle": None, "error_sql": GENERIC_DB_ERROR_MESSAGE}

# =========================================================
# FASE 2
# =========================================================
def consultar_fase2_historica(reporte):
    curp = normalizar_texto(reporte.get("curp"))
    nombre = normalizar_texto(reporte.get("nombre"))
    primer_apellido = normalizar_texto(reporte.get("primer_apellido"))
    segundo_apellido = normalizar_texto(reporte.get("segundo_apellido"))
    fecha_inicio, fecha_fin = calcular_fecha_inicio_historica(reporte.get("fecha_desaparicion"))

    if not fecha_inicio:
        return {
            "ejecutada": False,
            "coincidencias": [],
            "mensaje": "Fase 2 omitida por no contar con fecha_desaparicion válida"
        }

    query = """
    SELECT
        cc.AvalID,
        cc.ClienteID,
        cc.RFC,
        cc.CURP,
        cc.Nombre,
        cc.ApellidoPaterno,
        cc.ApellidoMaterno,
        cc.NombreCompleto,
        cc.RazonSocial,
        cc.Correo,
        cc.FechaNacimiento,
        cc.Genero,
        cc.Calle,
        cc.NoExterior,
        cc.NoInterior,
        cc.CodigoPostal,
        COALESCE(cc.UltimaAct, cc.Fecha) AS FechaEvento,
        ca.EmpresaID
    FROM CatAvales AS cc
    INNER JOIN CatClientes AS ca
        ON cc.ClienteID = ca.ClienteID
    WHERE ca.EmpresaID = ?
      AND UPPER(LTRIM(RTRIM(ISNULL(cc.CURP, '')))) = ?
      AND CAST(COALESCE(cc.UltimaAct, cc.Fecha) AS DATE) BETWEEN ? AND ?
    """

    params = [EMPRESA_ID, curp, fecha_inicio.strftime("%Y-%m-%d"), fecha_fin.strftime("%Y-%m-%d")]

    if nombre:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.Nombre, '')))) = ?"
        params.append(nombre)

    if primer_apellido:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.ApellidoPaterno, '')))) = ?"
        params.append(primer_apellido)

    if segundo_apellido:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.ApellidoMaterno, '')))) = ?"
        params.append(segundo_apellido)

    query += " ORDER BY COALESCE(cc.UltimaAct, cc.Fecha) ASC"

    registrar_auditoria(
        "CONSULTA_SQL_FASE2",
        reporte["id"],
        construir_resumen_sql_para_auditoria(query, params)
    )

    try:
        coincidencias = []
        with obtener_conexion_sql() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            if not rows:
                return {"ejecutada": True, "coincidencias": [], "mensaje": "Sin coincidencias fase 2"}

            columns = [column[0] for column in cursor.description]

            for row in rows:
                data = dict(zip(columns, row))
                detalle = {
                    "aval_id": str(data.get("AvalID")) if data.get("AvalID") else None,
                    "cliente_id": str(data.get("ClienteID")) if data.get("ClienteID") else None,
                    "rfc": valor_o_none(data.get("RFC")),
                    "curp": valor_o_none(data.get("CURP")),
                    "nombre": valor_o_none(data.get("Nombre")),
                    "primer_apellido": valor_o_none(data.get("ApellidoPaterno")),
                    "segundo_apellido": valor_o_none(data.get("ApellidoMaterno")),
                    "nombre_completo": valor_o_none(data.get("NombreCompleto")) or construir_nombre_completo(
                        data.get("Nombre"), data.get("ApellidoPaterno"), data.get("ApellidoMaterno")
                    ),
                    "razon_social": valor_o_none(data.get("RazonSocial")),
                    "correo": valor_o_none(data.get("Correo")),
                    "fecha_nacimiento": formato_fecha_iso(data.get("FechaNacimiento")),
                    "sexo_asignado": valor_o_none(data.get("Genero")),
                    "direccion": valor_o_none(data.get("Calle")),
                    "numero": " ".join([p for p in [valor_o_none(data.get("NoExterior")), valor_o_none(data.get("NoInterior"))] if p]) or None,
                    "codigo_postal": valor_o_none(data.get("CodigoPostal")),
                    "empresa_id": str(data.get("EmpresaID")) if data.get("EmpresaID") else None,
                    "fecha_evento": formato_fecha_iso(data.get("FechaEvento")),
                    "descripcion_lugar_evento": "Registro institucional histórico en CatAvales",
                    "tipo_evento": "REGISTRO ADMINISTRATIVO EN CATAVALES"
                }
                coincidencias.append(detalle)

        return {"ejecutada": True, "coincidencias": coincidencias, "mensaje": "Consulta histórica ejecutada"}

    except Exception as e:
        logger.error(f"Error SQL fase 2: {e}")
        return {"ejecutada": True, "coincidencias": [], "mensaje": GENERIC_DB_ERROR_MESSAGE}

# =========================================================
# FASE 3
# =========================================================
def consultar_fase3_continua(reporte):
    curp = normalizar_texto(reporte.get("curp"))
    nombre = normalizar_texto(reporte.get("nombre"))
    primer_apellido = normalizar_texto(reporte.get("primer_apellido"))
    segundo_apellido = normalizar_texto(reporte.get("segundo_apellido"))

    # 🔥 FIX: Pass native datetime object to SQL Server for safer comparison
    ultimo_corte = reporte.get("ultimo_corte_fase3")
    if ultimo_corte:
        try:
            # Parse ISO format from datetime.utcnow().isoformat()
            ultimo_corte_dt = datetime.fromisoformat(ultimo_corte)
        except (ValueError, TypeError):
            # Fallback a datetime actual
            ultimo_corte_dt = datetime.utcnow()
    else:
        ultimo_corte_dt = datetime.utcnow()

    query = """
    SELECT
        cc.AvalID,
        cc.ClienteID,
        cc.RFC,
        cc.CURP,
        cc.Nombre,
        cc.ApellidoPaterno,
        cc.ApellidoMaterno,
        cc.NombreCompleto,
        cc.RazonSocial,
        cc.Correo,
        cc.FechaNacimiento,
        cc.Genero,
        cc.Calle,
        cc.NoExterior,
        cc.NoInterior,
        cc.CodigoPostal,
        cc.Fecha AS FechaEvento,
        ca.EmpresaID
    FROM CatAvales AS cc
    INNER JOIN CatClientes AS ca
        ON cc.ClienteID = ca.ClienteID
    WHERE ca.EmpresaID = ?
      AND UPPER(LTRIM(RTRIM(ISNULL(cc.CURP, '')))) = ?
      AND ISDATE(cc.Fecha) = 1
      AND CONVERT(datetime, cc.Fecha, 120) > ?
    """

    params = [EMPRESA_ID, curp, ultimo_corte_dt]

    if nombre:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.Nombre, '')))) = ?"
        params.append(nombre)

    if primer_apellido:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.ApellidoPaterno, '')))) = ?"
        params.append(primer_apellido)

    if segundo_apellido:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.ApellidoMaterno, '')))) = ?"
        params.append(segundo_apellido)

    query += " ORDER BY CONVERT(datetime, cc.Fecha, 120) ASC"

    registrar_auditoria(
        "CONSULTA_SQL_FASE3",
        reporte["id"],
        construir_resumen_sql_para_auditoria(query, params)
    )

    try:
        coincidencias = []
        nuevo_corte = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        with obtener_conexion_sql() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            if not rows:
                return {"coincidencias": [], "nuevo_corte": nuevo_corte}

            columns = [column[0] for column in cursor.description]

            for row in rows:
                data = dict(zip(columns, row))
                detalle = {
                    "aval_id": str(data.get("AvalID")) if data.get("AvalID") else None,
                    "cliente_id": str(data.get("ClienteID")) if data.get("ClienteID") else None,
                    "rfc": valor_o_none(data.get("RFC")),
                    "curp": valor_o_none(data.get("CURP")),
                    "nombre": valor_o_none(data.get("Nombre")),
                    "primer_apellido": valor_o_none(data.get("ApellidoPaterno")),
                    "segundo_apellido": valor_o_none(data.get("ApellidoMaterno")),
                    "nombre_completo": valor_o_none(data.get("NombreCompleto")) or construir_nombre_completo(
                        data.get("Nombre"), data.get("ApellidoPaterno"), data.get("ApellidoMaterno")
                    ),
                    "razon_social": valor_o_none(data.get("RazonSocial")),
                    "correo": valor_o_none(data.get("Correo")),
                    "fecha_nacimiento": formato_fecha_iso(data.get("FechaNacimiento")),
                    "sexo_asignado": valor_o_none(data.get("Genero")),
                    "direccion": valor_o_none(data.get("Calle")),
                    "numero": " ".join([
                        p for p in [
                            valor_o_none(data.get("NoExterior")),
                            valor_o_none(data.get("NoInterior"))
                        ] if p
                    ]) or None,
                    "codigo_postal": valor_o_none(data.get("CodigoPostal")),
                    "empresa_id": str(data.get("EmpresaID")) if data.get("EmpresaID") else None,
                    "fecha_evento": formato_fecha_iso(data.get("FechaEvento")),
                    "descripcion_lugar_evento": "Registro institucional continuo en CatAvales",
                    "tipo_evento": "REGISTRO ADMINISTRATIVO EN CATAVALES"
                }
                coincidencias.append(detalle)

        return {"coincidencias": coincidencias, "nuevo_corte": nuevo_corte}

    except Exception as e:
        logger.error(f"Error SQL fase 3: {e}")
        return {
            "coincidencias": [],
            "nuevo_corte": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
# =========================================================
# PAYLOAD /notificar-coincidencia
# =========================================================
def construir_payload_notificacion(reporte, detalle, fase_busqueda):
    curp = valor_o_none(detalle.get("curp")) or valor_o_none(reporte.get("curp"))
    payload = {
        "curp": curp,
        "id": reporte["id"],
        "institucion_id": PUI_INSTITUCION_ID,
        "lugar_nacimiento": lugar_nacimiento_desde_curp(curp),
        "fase_busqueda": str(fase_busqueda),
    }

    nombre = valor_o_none(detalle.get("nombre"))
    primer_apellido = valor_o_none(detalle.get("primer_apellido"))
    segundo_apellido = valor_o_none(detalle.get("segundo_apellido"))

    if nombre or primer_apellido or segundo_apellido:
        payload["nombre_completo"] = {
            "nombre": nombre or "",
            "primer_apellido": primer_apellido or "",
            "segundo_apellido": segundo_apellido or "",
        }

    if detalle.get("fecha_nacimiento"):
        payload["fecha_nacimiento"] = detalle["fecha_nacimiento"]

    if detalle.get("sexo_asignado"):
        sexo = normalizar_texto(detalle["sexo_asignado"])
        payload["sexo_asignado"] = sexo if sexo in ("H", "M", "X") else "X"

    if detalle.get("correo"):
        payload["correo"] = detalle["correo"]

    domicilio_campos = {}
    if detalle.get("direccion"):
        domicilio_campos["direccion"] = detalle["direccion"]
    if detalle.get("numero"):
        domicilio_campos["numero"] = detalle["numero"]
    if detalle.get("codigo_postal"):
        domicilio_campos["codigo_postal"] = str(detalle["codigo_postal"])
    if domicilio_campos:
        payload["domicilio"] = domicilio_campos

    if str(fase_busqueda) in ("2", "3"):
        if detalle.get("tipo_evento"):
            payload["tipo_evento"] = detalle["tipo_evento"]
        if detalle.get("fecha_evento"):
            payload["fecha_evento"] = detalle["fecha_evento"]
        if detalle.get("descripcion_lugar_evento"):
            payload["descripcion_lugar_evento"] = detalle["descripcion_lugar_evento"]

        direccion_evento = {}
        if detalle.get("direccion"):
            direccion_evento["direccion"] = detalle["direccion"]
        if detalle.get("numero"):
            direccion_evento["numero"] = detalle["numero"]
        if detalle.get("codigo_postal"):
            direccion_evento["codigo_postal"] = str(detalle["codigo_postal"])
        if direccion_evento:
            payload["direccion_evento"] = direccion_evento

    return payload

# =========================================================
# ENVÍOS A PUI
# =========================================================
def notificar_coincidencia_pui(reporte, detalle, fase_busqueda):
    token_pui = obtener_token_pui()
    url = f"{PUI_BASE_URL.rstrip('/')}/notificar-coincidencia"
    payload = construir_payload_notificacion(reporte, detalle, fase_busqueda)

    hash_unico = generar_hash_coincidencia(reporte["id"], str(fase_busqueda), detalle)
    if existe_coincidencia_hash(hash_unico):
        registrar_auditoria("COINCIDENCIA_DUPLICADA_OMITIDA", reporte["id"], hash_unico)
        return True, payload, {"status_code": 200, "body": "Coincidencia duplicada omitida localmente"}

    headers = {
        "Authorization": f"Bearer {token_pui}",
        "Content-Type": "application/json; charset=utf-8"
    }

    for intento in range(3):
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=(5, REQUEST_TIMEOUT), verify=VERIFY_TLS, allow_redirects=False)
            respuesta = {"status_code": r.status_code, "body": r.text}

            registrar_auditoria(
                "ENVIO_NOTIFICAR_COINCIDENCIA",
                reporte["id"],
                {"payload": payload, "respuesta": {"status_code": respuesta.get("status_code")}}
            )
            if r.status_code == 200:
                guardar_coincidencia_local(reporte["id"], str(fase_busqueda), payload, respuesta, hash_unico)
                return True, payload, respuesta

        except requests.RequestException as e:
            logger.error(f"Intento {intento + 1} error notificar coincidencia: {e}")

        time.sleep(2 ** intento)

    return False, payload, {"status_code": 500, "body": "No fue posible notificar a la PUI"}

def enviar_busqueda_finalizada_pui(reporte_id):
    token_pui = obtener_token_pui()
    url = f"{PUI_BASE_URL.rstrip('/')}/busqueda-finalizada"
    payload = {
        "id": reporte_id,
        "institucion_id": PUI_INSTITUCION_ID
    }

    headers = {
        "Authorization": f"Bearer {token_pui}",
        "Content-Type": "application/json; charset=utf-8"
    }

    r = requests.post(url, json=payload, headers=headers, timeout=(5, REQUEST_TIMEOUT), verify=VERIFY_TLS, allow_redirects=False)

    registrar_auditoria(
        "ENVIO_BUSQUEDA_FINALIZADA",
        reporte_id,
        {"status_code": r.status_code, "payload": payload}
    )

    return r.status_code == 200, r.text

# =========================================================
# PROCESAMIENTO DE FASES
# =========================================================
def ejecutar_fase1(reporte):
    resultado_f1 = consultar_fase1_datos_basicos(
        curp=reporte["curp"],
        nombre=reporte.get("nombre"),
        primer_apellido=reporte.get("primer_apellido"),
        segundo_apellido=reporte.get("segundo_apellido")
    )

    if resultado_f1.get("error_sql"):
        actualizar_estatus_reporte_local(reporte["id"], "ERROR_FASE1", "1")
        return resultado_f1

    if resultado_f1.get("encontrado"):
        ok, payload, respuesta = notificar_coincidencia_pui(reporte, resultado_f1["detalle"], "1")
        if ok:
            actualizar_estatus_reporte_local(reporte["id"], "COINCIDENCIA_FASE1_NOTIFICADA", "1")
        else:
            actualizar_estatus_reporte_local(reporte["id"], "ERROR_NOTIFICACION_FASE1", "1")
    else:
        actualizar_estatus_reporte_local(reporte["id"], "SIN_COINCIDENCIA_FASE1", "1")

    return resultado_f1


def ejecutar_fase2(reporte):
    resultado = consultar_fase2_historica(reporte)

    if resultado["ejecutada"]:
        for detalle in resultado["coincidencias"]:
            notificar_coincidencia_pui(reporte, detalle, "2")

        try:
            ok_fin, body_fin = enviar_busqueda_finalizada_pui(reporte["id"])
            if ok_fin:
                actualizar_estatus_reporte_local(reporte["id"], "BUSQUEDA_HISTORICA_FINALIZADA", "2")
            else:
                actualizar_estatus_reporte_local(reporte["id"], "ERROR_BUSQUEDA_FINALIZADA", "2")
        except Exception as e:
            logger.error(f"Error enviando /busqueda-finalizada para {reporte['id']}: {e}")
            actualizar_estatus_reporte_local(reporte["id"], "ERROR_BUSQUEDA_FINALIZADA", "2")
    else:
        actualizar_estatus_reporte_local(reporte["id"], "FASE2_OMITIDA", "2")

    return resultado


def ejecutar_fase3_para_reporte(reporte):
    # Mark as processing to prevent duplicate processing in multi-instance deployments
    # Returns False if another process already claimed this report
    if not marcar_procesando_fase3(reporte["id"]):
        logger.info(f"Reporte {reporte['id']} ya está siendo procesado por otro worker, omitiendo")
        return {"coincidencias": [], "nuevo_corte": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}
    
    try:
        resultado = consultar_fase3_continua(reporte)

        for detalle in resultado["coincidencias"]:
            notificar_coincidencia_pui(reporte, detalle, "3")

        actualizar_corte_fase3(reporte["id"], resultado["nuevo_corte"])
        if resultado["coincidencias"]:
            actualizar_estatus_reporte_local(reporte["id"], "COINCIDENCIA_FASE3_NOTIFICADA", "3")

        return resultado
    finally:
        # Always unmark processing flag, even if an error occurs
        desmarcar_procesando_fase3(reporte["id"])

# =========================================================
# ENDPOINTS
# =========================================================
@app.route("/health", methods=["GET"])
def health():
    if HEALTH_REQUIRE_TOKEN:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "No autorizado"}), 401
        try:
            token = auth.replace("Bearer ", "", 1).strip()
            jwt.decode(
                token,
                JWT_SECRET,
                algorithms=["HS256"],
                audience="pui-api",
                issuer="pui-webhook",
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "institucion_id"]}
            )
        except Exception:
            return jsonify({"error": "No autorizado"}), 401
    return jsonify({"status": "ok"}), 200

@app.route("/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"error": "Content-Type debe ser application/json"}), 415
    ip = obtener_ip_cliente()
    
    now = datetime.utcnow()
    
    with LOGIN_ATTEMPTS_LOCK:
        # Clean up old attempts (older than 15 minutes)
        cutoff = now - timedelta(minutes=15)
        LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS.get(ip, []) if t > cutoff]
        
        # Periodic cleanup of old IPs to prevent memory growth
        if len(LOGIN_ATTEMPTS) > 10000:
            cleaned_attempts = {
                ip_key: times for ip_key, times in LOGIN_ATTEMPTS.items()
                if any(t > cutoff for t in times)
            }
            LOGIN_ATTEMPTS.clear()
            LOGIN_ATTEMPTS.update(cleaned_attempts)
        
        # Check if rate limit exceeded
        if len(LOGIN_ATTEMPTS.get(ip, [])) >= 5:
            logger.warning(f"Rate limit exceeded for IP: {ip}")
            return jsonify({"error": "Demasiados intentos. Intente más tarde."}), 429
    
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "JSON no enviado"}), 400

    usuario = (data.get("usuario") or "").strip()
    clave = (data.get("clave") or "").strip()

    if not usuario or not clave:
        return jsonify({"error": "Credenciales inválidas"}), 403

    if usuario not in USUARIOS or not verificar_credenciales(usuario, clave):
        # Track failed attempt
        with LOGIN_ATTEMPTS_LOCK:
            LOGIN_ATTEMPTS.setdefault(ip, []).append(now)
        logger.warning(f"Login fallido para usuario '{sanitizar_valor_sensible(usuario)}' desde IP: {ip}")
        return jsonify({"error": "Credenciales inválidas"}), 403

    # Reset attempts on successful login and remove empty IPs
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS[ip] = []
        # Clean up empty IPs to prevent memory growth
        for ip_key in list(LOGIN_ATTEMPTS.keys()):
            if not LOGIN_ATTEMPTS[ip_key]:
                del LOGIN_ATTEMPTS[ip_key]
    
    token = generar_token_local(usuario)

    return jsonify({
        "token": token,
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600
    }), 200

@app.route("/activar-reporte", methods=["POST"])
@requiere_token
def activar_reporte():
    data, error = validar_json(["id", "curp"])
    if error:
        return jsonify({"error": error}), 400

    ok_id, id_validado = validar_id_busqueda(data.get("id"))
    if not ok_id:
        return jsonify({"error": id_validado}), 400

    ok_curp, curp_validada = validar_curp(data.get("curp"))
    if not ok_curp:
        return jsonify({"error": curp_validada}), 400

    try:
        reporte = validar_campos_reporte({**data, "id": id_validado, "curp": curp_validada})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    guardar_reporte_local(reporte, g.usuario_id, "RECIBIDO", "1")
    registrar_auditoria("ACTIVAR_REPORTE_RECIBIDO", reporte["id"], sanitizar_para_log(reporte))

    ejecutar_fase1(reporte)
    ejecutar_fase2(reporte)

    return jsonify({
        "message": "La solicitud de activación del reporte de búsqueda se recibió correctamente."
    }), 200


@app.route("/activar-reporte-prueba", methods=["POST"])
@requiere_token
def activar_reporte_prueba():
    data, error = validar_json(["id", "curp"])
    if error:
        return jsonify({"error": error}), 400

    ok_id, id_validado = validar_id_busqueda(data.get("id"))
    if not ok_id:
        return jsonify({"error": id_validado}), 400

    ok_curp, curp_validada = validar_curp(data.get("curp"))
    if not ok_curp:
        return jsonify({"error": curp_validada}), 400

    try:
        reporte = validar_campos_reporte({**data, "id": id_validado, "curp": curp_validada})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    guardar_reporte_local(reporte, g.usuario_id, "RECIBIDO_PRUEBA", "1")
    registrar_auditoria("ACTIVAR_REPORTE_PRUEBA_RECIBIDO", reporte["id"], sanitizar_para_log(reporte))

    resultado_f1 = consultar_fase1_datos_basicos(
        curp=reporte["curp"],
        nombre=reporte.get("nombre"),
        primer_apellido=reporte.get("primer_apellido"),
        segundo_apellido=reporte.get("segundo_apellido")
    )

    estatus = "PRUEBA_COINCIDENCIA" if resultado_f1.get("encontrado") else "PRUEBA_SIN_COINCIDENCIA"
    actualizar_estatus_reporte_local(reporte["id"], estatus, "1")

    return jsonify({
        "codigo": "200",
        "mensaje": "Reporte de prueba recibido correctamente",
        "id": reporte["id"],
        "curp": reporte["curp"],
        "estatus": estatus,
        "coincidencia": bool(resultado_f1.get("encontrado")),
        "fase": resultado_f1.get("fase"),
        "detalle": resultado_f1.get("detalle"),
        "error_sql": resultado_f1.get("error_sql")
    }), 200


@app.route("/desactivar-reporte", methods=["POST"])
@requiere_token
def desactivar_reporte():
    data, error = validar_json(["id"])
    if error:
        return jsonify({"error": error}), 400

    ok_id, id_validado = validar_id_busqueda(data.get("id"))
    if not ok_id:
        return jsonify({"error": id_validado}), 400

    desactivar_fase3_local(id_validado)
    registrar_auditoria("DESACTIVAR_REPORTE", id_validado, "Reporte desactivado por solicitud de PUI")

    return jsonify({
        "message": "Registro de finalización de búsqueda histórica guardado correctamente"
    }), 200

# =========================================================
# ENDPOINTS PARA REVISAR MOVIMIENTOS / PRUEBAS
# =========================================================
@app.route("/reportes", methods=["GET"])
@requiere_token
def listar_reportes():
    limit = limpiar_entero_positivo(request.args.get("limit", default=100, type=int), default_value=100, max_value=500)
    offset = limpiar_entero_positivo(request.args.get("offset", default=0, type=int), default_value=0, max_value=1000000)
    estatus = request.args.get("estatus", default=None, type=str)
    
    # Enforce max limit of 500
    limit = min(limit, 500)

    with obtener_conexion_local() as conn:
        if estatus:
            rows = conn.execute(
                """
                SELECT *
                FROM reportes
                WHERE estatus = ?
                ORDER BY fecha_actualizacion DESC
                LIMIT ? OFFSET ?
                """,
                (estatus, limit, offset)
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT *
                FROM reportes
                ORDER BY fecha_actualizacion DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            ).fetchall()

    return jsonify({
        "total": len(rows),
        "items": [row_to_dict(r) for r in rows]
    }), 200


@app.route("/reportes/<reporte_id>", methods=["GET"])
@requiere_token
def obtener_reporte(reporte_id):
    ok_id, reporte_id = validar_id_busqueda(reporte_id)
    if not ok_id:
        return jsonify({"error": reporte_id}), 400
    with obtener_conexion_local() as conn:
        row = conn.execute(
            "SELECT * FROM reportes WHERE id = ?",
            (reporte_id,)
        ).fetchone()

    if not row:
        return jsonify({"error": "Reporte no encontrado"}), 404

    return jsonify(row_to_dict(row)), 200


@app.route("/coincidencias", methods=["GET"])
@requiere_token
def listar_coincidencias():
    limit = limpiar_entero_positivo(request.args.get("limit", default=100, type=int), default_value=100, max_value=500)
    offset = limpiar_entero_positivo(request.args.get("offset", default=0, type=int), default_value=0, max_value=1000000)
    fase = request.args.get("fase", default=None, type=str)
    
    # Enforce max limit of 500
    limit = min(limit, 500)

    with obtener_conexion_local() as conn:
        if fase:
            rows = conn.execute(
                """
                SELECT *
                FROM coincidencias
                WHERE fase_busqueda = ?
                ORDER BY fecha_envio DESC
                LIMIT ? OFFSET ?
                """,
                (fase, limit, offset)
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT *
                FROM coincidencias
                ORDER BY fecha_envio DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            ).fetchall()

    return jsonify({
        "total": len(rows),
        "items": [row_to_dict(r) for r in rows]
    }), 200


@app.route("/coincidencias/<reporte_id>", methods=["GET"])
@requiere_token
def obtener_coincidencias_por_reporte(reporte_id):
    ok_id, reporte_id = validar_id_busqueda(reporte_id)
    if not ok_id:
        return jsonify({"error": reporte_id}), 400
    with obtener_conexion_local() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM coincidencias
            WHERE reporte_id = ?
            ORDER BY fecha_envio DESC
            LIMIT 500
            """,
            (reporte_id,)
        ).fetchall()

    return jsonify({
        "reporte_id": reporte_id,
        "total": len(rows),
        "items": [row_to_dict(r) for r in rows]
    }), 200


@app.route("/auditoria", methods=["GET"])
@requiere_token
def listar_auditoria():
    limit = limpiar_entero_positivo(request.args.get("limit", default=200, type=int), default_value=200, max_value=500)
    offset = limpiar_entero_positivo(request.args.get("offset", default=0, type=int), default_value=0, max_value=1000000)
    evento = request.args.get("evento", default=None, type=str)
    referencia_id = request.args.get("referencia_id", default=None, type=str)
    
    # Enforce max limit of 500
    limit = min(limit, 500)

    query = "SELECT * FROM auditoria"
    params = []
    filtros = []

    if evento:
        filtros.append("evento = ?")
        params.append(evento)

    if referencia_id:
        filtros.append("referencia_id = ?")
        params.append(referencia_id)

    if filtros:
        query += " WHERE " + " AND ".join(filtros)

    query += " ORDER BY fecha_evento DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with obtener_conexion_local() as conn:
        rows = conn.execute(query, params).fetchall()

    return jsonify({
        "total": len(rows),
        "items": [row_to_dict(r) for r in rows]
    }), 200

# =========================================================
# ERRORES
# =========================================================
@app.errorhandler(400)
def solicitud_invalida(_):
    return jsonify({"error": "Solicitud inválida"}), 400

@app.errorhandler(404)
def no_encontrado(_):
    return jsonify({"error": "No encontrado"}), 404

@app.errorhandler(413)
def payload_demasiado_grande(_):
    return jsonify({"error": "Payload demasiado grande"}), 413

@app.errorhandler(415)
def media_type_invalido(_):
    return jsonify({"error": "Content-Type debe ser application/json"}), 415

@app.errorhandler(405)
def metodo_no_permitido(_):
    return jsonify({"error": "Method Not Allowed"}), 405

@app.errorhandler(500)
def error_interno(_):
    return jsonify({"error": "Error interno del servidor"}), 500

# =========================================================
# PREVALIDACIÓN REQUEST
# =========================================================
@app.before_request
def enforce_json_content_type():
    return require_json_request()

# =========================================================
# LOG REQUEST
# =========================================================
@app.before_request
def log_request():
    g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    ip = obtener_ip_cliente()
    logger.info(f"[HTTP] {request.method} {request.path} from {ip} request_id={g.request_id}")
    
    data = None
    if request.is_json:
        try:
            data = request.get_json(silent=True)
        except Exception:
            data = None

    if isinstance(data, dict):
        data_log = dict(data)
        # Filter sensitive fields for compliance with data protection regulations
        data_log = sanitizar_para_log(data_log)
        data_str = json.dumps(data_log, ensure_ascii=False)
        if len(data_str) > 1000:
            data_str = data_str[:1000] + "... (truncated)"
        logger.info(f"[DATA] Request body (filtered): {data_str}")
    elif data:
        data_str = str(data)
        if len(data_str) > 1000:
            data_str = data_str[:1000] + "... (truncated)"
        logger.info(f"[DATA] Request body: {data_str}")

# =========================================================
# WORKER FASE 3
# =========================================================
def worker_fase3():
    logger.info("Hilo de fase 3 iniciado")
    cleanup_counter = 0
    while not PHASE3_STOP_EVENT.is_set():
        try:
            reportes = obtener_reportes_fase3_activos()
            for reporte in reportes:
                if PHASE3_STOP_EVENT.is_set():
                    break
                try:
                    ejecutar_fase3_para_reporte(reporte)
                except Exception as inner_e:
                    logger.error(f"Error procesando reporte {reporte.get('id', 'unknown')}: {inner_e}")
            
            # Run DB cleanup every 10 cycles (approximately every hour with default interval)
            cleanup_counter += 1
            if cleanup_counter >= 10:
                try:
                    limpiar_db_antigua()
                except Exception as cleanup_e:
                    logger.error(f"Error en limpieza DB: {cleanup_e}")
                cleanup_counter = 0
                
        except Exception as e:
            import traceback
            logger.error(f"Error en worker fase 3: {e}\n{traceback.format_exc()}")

        # Wait with timeout to allow responsive shutdown
        PHASE3_STOP_EVENT.wait(PHASE3_INTERVAL_SECONDS)

    logger.info("Hilo de fase 3 detenido limpiamente")


def iniciar_worker_fase3():
    global PHASE3_THREAD
    if not ENABLE_PHASE3_THREAD:
        logger.info("Fase 3 automática deshabilitada")
        return
    if PHASE3_THREAD and PHASE3_THREAD.is_alive():
        return

    PHASE3_THREAD = threading.Thread(target=worker_fase3, daemon=True)
    PHASE3_THREAD.start()
    logger.info("Worker fase 3 iniciado en hilo separado")

# =========================================================
# INIT
# =========================================================
inicializar_db_local()
iniciar_worker_fase3()

# =========================================================
# LOCAL
# =========================================================
if __name__ == "__main__":
    logger.info(f"Server listo en http://0.0.0.0:{PORT}")
    serve(app, host="0.0.0.0", port=PORT)