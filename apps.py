from flask import Flask, request, Response, jsonify
import requests
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)

# 🔧 CONFIG
PUBLIC_URL = "http://enviacorreo.balor.mx:8081/PUI"
SECRET = "super_secret"

# =========================
# 🔐 GENERAR TOKEN
# =========================
def generar_token(institucion_id):
    payload = {
        "institucion_id": institucion_id,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


# =========================
# 🔐 VALIDAR TOKEN
# =========================
def validar_token():
    auth = request.headers.get("Authorization")

    if not auth:
        return False

    try:
        token = auth.replace("Bearer ", "")
        jwt.decode(token, SECRET, algorithms=["HS256"])
        return True
    except:
        return False


# =========================
# 🔐 LOGIN (PUI)
# =========================
@app.route('/login', methods=['POST'])
def login():
    data = request.json

    if not data or not data.get("institucion_id") or not data.get("clave"):
        return jsonify({
            "codigo": "401",
            "mensaje": "Credenciales inválidas"
        }), 401

    token = generar_token(data["institucion_id"])

    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600
    })


# =========================
# 📡 ACTIVAR REPORTE
# =========================
@app.route('/activar-reporte', methods=['POST'])
def activar_reporte():

    if not validar_token():
        return jsonify({
            "codigo": "401",
            "mensaje": "No autorizado"
        }), 401

    data = request.json
    print("📥 Activar reporte:", data)

    # 🔥 AQUÍ VA TU LÓGICA
    # buscar en tu sistema
    # iniciar procesos async si quieres

    return jsonify({
        "codigo": "200",
        "mensaje": "Reporte recibido correctamente"
    })


# =========================
# 🔁 DESACTIVAR REPORTE
# =========================
@app.route('/desactivar-reporte', methods=['POST'])
def desactivar_reporte():

    if not validar_token():
        return jsonify({
            "codigo": "401",
            "mensaje": "No autorizado"
        }), 401

    data = request.json
    print("❌ Desactivar reporte:", data)

    return jsonify({
        "codigo": "200",
        "mensaje": "Reporte desactivado"
    })


# =========================
# ✅ BUSQUEDA FINALIZADA
# =========================
@app.route('/busqueda-finalizada', methods=['POST'])
def busqueda_finalizada():

    if not validar_token():
        return jsonify({
            "codigo": "401",
            "mensaje": "No autorizado"
        }), 401

    data = request.json
    print("✅ Búsqueda finalizada:", data)

    return jsonify({
        "codigo": "200",
        "mensaje": "Confirmación recibida"
    })


# =========================
# 📡 NOTIFICAR COINCIDENCIA (TÚ → PUI)
# =========================
def notificar_coincidencia(data, fase):

    payload = {
        "curp": data.get("curp"),
        "folio": data.get("folio"),
        "fase": str(fase),
        "descripcion": "Coincidencia encontrada"
    }

    headers = {
        "Authorization": "Bearer TU_TOKEN_PUI",
        "Content-Type": "application/json"
    }

    try:
        r = requests.post(
            "https://pui.gob.mx/api/notificar-coincidencia",
            json=payload,
            headers=headers
        )
        print("📤 Notificado:", r.status_code)
    except Exception as e:
        print("Error notificando:", e)


# =========================
# 🌐 PROXY (OPCIONAL)
# =========================
@app.route('/', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE'])
@app.route('/<path:path>', methods=['GET','POST','PUT','DELETE'])
def proxy(path):

    # 🔥 IGNORAR ENDPOINTS PUI
    if path in ["login", "activar-reporte", "desactivar-reporte", "busqueda-finalizada"]:
        return jsonify({"error": "Ruta no encontrada"}), 404

    return jsonify({
        "mensaje": "Ruta no utilizada para PUI"
    })


# =========================
# 🧾 LOG
# =========================
@app.before_request
def log_request():
    print(f"{request.method} {request.path}")


# =========================
# 🚀 RUN
# =========================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)