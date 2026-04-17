import json
from cryptography.fernet import Fernet

# Genera una vez tu llave con:
# python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

KEY = b"8LPSsZxUUBFznoggugkRtnN08YSn3_GgIcGRMMOq2P8="

config = {
    "PORT": 5000,
    "APP_SECRET": "X9f7!kP4v2@bT8mZ1q#R6wL0yE3uS5cNrkjacahc",
    "USUARIOS": {
        "PUI": "Jsrv0906BDI09061656*"
    },

    "SQL_SERVER": "192.168.10.238",
    "SQL_DATABASE": "Factoraje",
    "SQL_USER": "Sistemas",
    "SQL_PASSWORD": "Sys_acces#05;",
    "SQL_DRIVER": "{ODBC Driver 17 for SQL Server}",
    "EMPRESA_ID": "FA764836-BB07-4EB3-9B30-2B69206174C2",

    "PUI_BASE_URL": "https://pui.gob.mx/api/notificar-coincidencia",
    "PUI_INSTITUCION_ID": "RFC_CON_HOMOCLAVE_DE_TU_INSTITUCION",
    "PUI_CLAVE": "CLAVE_REAL_PUI",

    "LOCAL_DB_PATH": "pui_local.db",
    "REQUEST_TIMEOUT": 15,
    "PHASE3_INTERVAL_SECONDS": 3600,
    "ENABLE_PHASE3_THREAD": True
}

fernet = Fernet(KEY)
encrypted = fernet.encrypt(json.dumps(config).encode("utf-8"))

with open("config.enc", "wb") as f:
    f.write(encrypted)

print("config.enc generado correctamente")