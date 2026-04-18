from dotenv import load_dotenv
load_dotenv()

import os
import json
import time
import sqlite3
import logging
import sys
import threading
from datetime import datetime, timedelta
from functools import wraps

import jwt
import pyodbc
import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, request, jsonify, g

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
JWT_SECRET = os.getenv("JWT_SECRET")
APP_USER = os.getenv("APP_USER")
APP_PASSWORD = os.getenv("APP_PASSWORD")

if not JWT_SECRET:
    raise ValueError("Falta JWT_SECRET")

if not APP_USER or not APP_PASSWORD:
    raise ValueError("Faltan credenciales APP_USER / APP_PASSWORD")

USUARIOS = {
    APP_USER: APP_PASSWORD
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

PHASE3_INTERVAL_SECONDS = int(CONFIG.get("PHASE3_INTERVAL_SECONDS", 3600))
ENABLE_PHASE3_THREAD = CONFIG.get("ENABLE_PHASE3_THREAD", True)

# CACHE TOKEN
PUI_TOKEN_CACHE = {
    "token": None,
    "exp": None
}

# THREAD
PHASE3_THREAD = None
PHASE3_STOP_EVENT = threading.Event()

# =========================================================
# LOGGING
# =========================================================
logger = logging.getLogger("app")
logger.setLevel(logging.INFO)

if not logger.handlers:
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler("app.log")
    fh.setFormatter(formatter)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

# =========================================================
# FLASK
# =========================================================
app = Flask(__name__)

# =========================================================
# MAPEO CURP -> LUGAR_NACIMIENTO
# =========================================================
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
def obtener_conexion_local():
    conn = sqlite3.connect(LOCAL_DB_PATH)
    conn.row_factory = sqlite3.Row
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
            activa_fase3 INTEGER DEFAULT 1
        )
        """)

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

        conn.commit()


def registrar_auditoria(evento, referencia_id=None, detalle=None):
    with obtener_conexion_local() as conn:
        conn.execute(
            """
            INSERT INTO auditoria (evento, referencia_id, detalle, fecha_evento)
            VALUES (?, ?, ?, ?)
            """,
            (evento, referencia_id, detalle, datetime.utcnow().isoformat())
        )
        conn.commit()


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
                fecha_actualizacion=excluded.fecha_actualizacion
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


def guardar_coincidencia_local(reporte_id, fase_busqueda, payload, respuesta_pui, hash_unico):
    with obtener_conexion_local() as conn:
        conn.execute(
            """
            INSERT INTO coincidencias (reporte_id, fase_busqueda, payload_json, respuesta_pui_json, fecha_envio, hash_unico)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                reporte_id,
                fase_busqueda,
                json.dumps(payload, ensure_ascii=False),
                json.dumps(respuesta_pui, ensure_ascii=False),
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


def obtener_reportes_fase3_activos():
    with obtener_conexion_local() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM reportes
            WHERE activa_fase3 = 1
              AND estatus NOT IN ('DESACTIVADO')
            """
        ).fetchall()
        return [dict(r) for r in rows]


def row_to_dict(row):
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}

# =========================================================
# HELPERS
# =========================================================
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

    hace_12_anios = hoy - timedelta(days=12 * 365)
    if f < hace_12_anios:
        f = hace_12_anios
    return f, hoy


def generar_hash_coincidencia(reporte_id, fase_busqueda, detalle):
    base = {
        "reporte_id": reporte_id,
        "fase_busqueda": fase_busqueda,
        "cliente_id": detalle.get("cliente_id"),
        "aval_id": detalle.get("aval_id"),
        "fecha_evento": detalle.get("fecha_evento"),
        "curp": detalle.get("curp"),
    }
    return json.dumps(base, sort_keys=True, ensure_ascii=False)

# =========================================================
# VALIDACIONES
# =========================================================
def validar_json(campos_obligatorios):
    data = request.get_json(silent=True)

    if not data:
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
    if not curp.isalnum():
        return False, "CURP debe contener sólo letras y números"
    return True, curp


def validar_id_busqueda(id_busqueda):
    if not isinstance(id_busqueda, str):
        return False, "ID inválido"
    id_busqueda = id_busqueda.strip()
    if len(id_busqueda) < 36 or len(id_busqueda) > 75:
        return False, "ID debe tener entre 36 y 75 caracteres"
    return True, id_busqueda

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
        "TrustServerCertificate=yes;"
    )
    return pyodbc.connect(conn_str, timeout=REQUEST_TIMEOUT)

# =========================================================
# JWT LOCAL
# =========================================================
def generar_token_local(usuario):
    payload = {
        "institucion_id": usuario,
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    #return jwt.encode(payload, SECRET, algorithm="HS256")
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


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
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            g.usuario_id = decoded["institucion_id"]

            if g.usuario_id != "PUI":
                return jsonify({"codigo": "403", "mensaje": "Sin permisos"}), 403

        except jwt.ExpiredSignatureError:
            return jsonify({"codigo": "401", "mensaje": "Token expirado"}), 401
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

    r = requests.post(
        url,
        json=payload,
        headers={"Content-Type": "application/json; charset=utf-8"},
        timeout=REQUEST_TIMEOUT
    )
    r.raise_for_status()
    data = r.json()

    token = data.get("token") or data.get("access_token")
    if not token:
        raise ValueError("La PUI no devolvió token")

    expires_in = int(data.get("expires_in", 3600))
    margen = max(60, int(expires_in * 0.20))
    PUI_TOKEN_CACHE["token"] = token
    PUI_TOKEN_CACHE["exp"] = ahora + timedelta(seconds=(expires_in - margen))
    return token

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
        json.dumps({"query": query, "params": params}, ensure_ascii=False)
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
        return {"encontrado": False, "fase": "1", "detalle": None, "error_sql": str(e)}

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
        json.dumps({"query": query, "params": params}, ensure_ascii=False)
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
        return {"ejecutada": True, "coincidencias": [], "mensaje": str(e)}

# =========================================================
# FASE 3
# =========================================================
def consultar_fase3_continua(reporte):
    curp = normalizar_texto(reporte.get("curp"))
    nombre = normalizar_texto(reporte.get("nombre"))
    primer_apellido = normalizar_texto(reporte.get("primer_apellido"))
    segundo_apellido = normalizar_texto(reporte.get("segundo_apellido"))

    # 🔥 FIX: formato compatible con SQL Server 2008
    ultimo_corte = reporte.get("ultimo_corte_fase3")
    if ultimo_corte:
        try:
            # intenta normalizar si viene en ISO
            ultimo_corte = datetime.fromisoformat(ultimo_corte).strftime("%Y-%m-%d %H:%M:%S")
        except:
            ultimo_corte = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    else:
        ultimo_corte = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

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
      AND CONVERT(datetime, cc.Fecha) > CONVERT(datetime, ?, 120)
    """

    params = [EMPRESA_ID, curp, ultimo_corte]

    if nombre:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.Nombre, '')))) = ?"
        params.append(nombre)

    if primer_apellido:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.ApellidoPaterno, '')))) = ?"
        params.append(primer_apellido)

    if segundo_apellido:
        query += " AND UPPER(LTRIM(RTRIM(ISNULL(cc.ApellidoMaterno, '')))) = ?"
        params.append(segundo_apellido)

    query += " ORDER BY CONVERT(datetime, cc.Fecha) ASC"

    registrar_auditoria(
        "CONSULTA_SQL_FASE3",
        reporte["id"],
        json.dumps({"query": query, "params": params}, ensure_ascii=False)
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
            r = requests.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
            respuesta = {"status_code": r.status_code, "body": r.text}

            registrar_auditoria(
                "ENVIO_NOTIFICAR_COINCIDENCIA",
                reporte["id"],
                json.dumps({"payload": payload, "respuesta": respuesta}, ensure_ascii=False)
            )

            if r.status_code == 200:
                guardar_coincidencia_local(reporte["id"], str(fase_busqueda), payload, respuesta, hash_unico)
                return True, payload, respuesta

        except requests.RequestException as e:
            logger.error(f"Intento {intento + 1} error notificar coincidencia: {e}")

        time.sleep(2)

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

    r = requests.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)

    registrar_auditoria(
        "ENVIO_BUSQUEDA_FINALIZADA",
        reporte_id,
        json.dumps({"status_code": r.status_code, "body": r.text, "payload": payload}, ensure_ascii=False)
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
    resultado = consultar_fase3_continua(reporte)

    for detalle in resultado["coincidencias"]:
        notificar_coincidencia_pui(reporte, detalle, "3")

    actualizar_corte_fase3(reporte["id"], resultado["nuevo_corte"])
    if resultado["coincidencias"]:
        actualizar_estatus_reporte_local(reporte["id"], "COINCIDENCIA_FASE3_NOTIFICADA", "3")

    return resultado

# =========================================================
# WORKER FASE 3
# =========================================================
def worker_fase3():
    logger.info("Hilo de fase 3 iniciado")
    while not PHASE3_STOP_EVENT.is_set():
        try:
            reportes = obtener_reportes_fase3_activos()
            for reporte in reportes:
                ejecutar_fase3_para_reporte(reporte)
        except Exception as e:
            logger.error(f"Error en worker fase 3: {e}")

        PHASE3_STOP_EVENT.wait(PHASE3_INTERVAL_SECONDS)

    logger.info("Hilo de fase 3 detenido")


def iniciar_worker_fase3():
    global PHASE3_THREAD
    if not ENABLE_PHASE3_THREAD:
        logger.info("Fase 3 automática deshabilitada")
        return
    if PHASE3_THREAD and PHASE3_THREAD.is_alive():
        return

    PHASE3_THREAD = threading.Thread(target=worker_fase3, daemon=True)
    PHASE3_THREAD.start()

# =========================================================
# ENDPOINTS
# =========================================================
@app.route("/login", methods=["POST"])
def login():

    print(">>> ENTRE A LOGIN <<<")
    print("USUARIOS CONFIG:", USUARIOS)
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "JSON no enviado"}), 400

    usuario = (data.get("usuario") or "").strip()
    clave = (data.get("clave") or "").strip()

    print("USUARIO:", usuario)
    print("CLAVE:", clave)

    if not usuario or not clave:
        return jsonify({"error": "Credenciales inválidas"}), 403

    if usuario not in USUARIOS or USUARIOS[usuario] != clave:
        return jsonify({"error": "Credenciales inválidas"}), 403

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

    reporte = {
        "id": id_validado,
        "curp": curp_validada,
        "nombre": valor_o_none(data.get("nombre")),
        "primer_apellido": valor_o_none(data.get("primer_apellido")),
        "segundo_apellido": valor_o_none(data.get("segundo_apellido")),
        "fecha_nacimiento": valor_o_none(data.get("fecha_nacimiento")),
        "fecha_desaparicion": valor_o_none(data.get("fecha_desaparicion")),
        "lugar_nacimiento": valor_o_none(data.get("lugar_nacimiento")) or lugar_nacimiento_desde_curp(curp_validada),
        "sexo_asignado": valor_o_none(data.get("sexo_asignado")),
        "telefono": valor_o_none(data.get("telefono")),
        "correo": valor_o_none(data.get("correo")),
        "direccion": valor_o_none(data.get("direccion")),
        "calle": valor_o_none(data.get("calle")),
        "numero": valor_o_none(data.get("numero")),
        "colonia": valor_o_none(data.get("colonia")),
        "codigo_postal": valor_o_none(data.get("codigo_postal")),
        "municipio_o_alcaldia": valor_o_none(data.get("municipio_o_alcaldia")),
        "entidad_federativa": valor_o_none(data.get("entidad_federativa")),
    }

    guardar_reporte_local(reporte, g.usuario_id, "RECIBIDO", "1")
    registrar_auditoria("ACTIVAR_REPORTE_RECIBIDO", reporte["id"], json.dumps(reporte, ensure_ascii=False))

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

    reporte = {
        "id": id_validado,
        "curp": curp_validada,
        "nombre": valor_o_none(data.get("nombre")),
        "primer_apellido": valor_o_none(data.get("primer_apellido")),
        "segundo_apellido": valor_o_none(data.get("segundo_apellido")),
        "fecha_nacimiento": valor_o_none(data.get("fecha_nacimiento")),
        "fecha_desaparicion": valor_o_none(data.get("fecha_desaparicion")),
        "lugar_nacimiento": valor_o_none(data.get("lugar_nacimiento")) or lugar_nacimiento_desde_curp(curp_validada),
        "sexo_asignado": valor_o_none(data.get("sexo_asignado")),
        "telefono": valor_o_none(data.get("telefono")),
        "correo": valor_o_none(data.get("correo")),
        "direccion": valor_o_none(data.get("direccion")),
        "calle": valor_o_none(data.get("calle")),
        "numero": valor_o_none(data.get("numero")),
        "colonia": valor_o_none(data.get("colonia")),
        "codigo_postal": valor_o_none(data.get("codigo_postal")),
        "municipio_o_alcaldia": valor_o_none(data.get("municipio_o_alcaldia")),
        "entidad_federativa": valor_o_none(data.get("entidad_federativa")),
    }

    guardar_reporte_local(reporte, g.usuario_id, "RECIBIDO_PRUEBA", "1")
    registrar_auditoria("ACTIVAR_REPORTE_PRUEBA_RECIBIDO", reporte["id"], json.dumps(reporte, ensure_ascii=False))

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
    limit = request.args.get("limit", default=100, type=int)
    offset = request.args.get("offset", default=0, type=int)
    estatus = request.args.get("estatus", default=None, type=str)

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
    limit = request.args.get("limit", default=100, type=int)
    offset = request.args.get("offset", default=0, type=int)
    fase = request.args.get("fase", default=None, type=str)

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
    with obtener_conexion_local() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM coincidencias
            WHERE reporte_id = ?
            ORDER BY fecha_envio DESC
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
    limit = request.args.get("limit", default=200, type=int)
    offset = request.args.get("offset", default=0, type=int)
    evento = request.args.get("evento", default=None, type=str)
    referencia_id = request.args.get("referencia_id", default=None, type=str)

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
@app.errorhandler(405)
def metodo_no_permitido(_):
    return jsonify({"error": "Method Not Allowed"}), 405


@app.errorhandler(500)
def error_interno(_):
    return jsonify({"error": "Error interno del servidor"}), 500

# =========================================================
# LOG REQUEST
# =========================================================
@app.before_request
def log_request():
    try:
        data = request.get_json(silent=True)
    except Exception:
        data = None

    if request.path == "/login" and isinstance(data, dict):
        data_log = dict(data)
        if "clave" in data_log:
            data_log["clave"] = "***"
    else:
        data_log = data

    logger.info(f"{request.remote_addr} {request.method} {request.path} - Body: {data_log}")

# =========================================================
# WORKER FASE 3
# =========================================================
def worker_fase3():
    logger.info("Hilo de fase 3 iniciado")
    while not PHASE3_STOP_EVENT.is_set():
        try:
            reportes = obtener_reportes_fase3_activos()
            for reporte in reportes:
                ejecutar_fase3_para_reporte(reporte)
        except Exception as e:
            logger.error(f"Error en worker fase 3: {e}")

        PHASE3_STOP_EVENT.wait(PHASE3_INTERVAL_SECONDS)

    logger.info("Hilo de fase 3 detenido")


def iniciar_worker_fase3():
    global PHASE3_THREAD
    if not ENABLE_PHASE3_THREAD:
        logger.info("Fase 3 automática deshabilitada")
        return
    if PHASE3_THREAD and PHASE3_THREAD.is_alive():
        return

    PHASE3_THREAD = threading.Thread(target=worker_fase3, daemon=True)
    PHASE3_THREAD.start()

# =========================================================
# INIT
# =========================================================
inicializar_db_local()
iniciar_worker_fase3()

# =========================================================
# LOCAL
# =========================================================
if __name__ == "__main__":
    logger.info(f"Server listo en http://localhost:{PORT}")
    app.run(host="localhost", port=PORT)