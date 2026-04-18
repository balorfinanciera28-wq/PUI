from waitress import serve
from appsi import app

print("🔥 APP CARGADA:", app)
print("🔥 RUTAS:")
print(app.url_map)

serve(app, host="0.0.0.0", port=5000)