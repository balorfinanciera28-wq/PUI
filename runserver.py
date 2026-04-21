from waitress import serve
from appsi import app

serve(app, host="0.0.0.0", port=5000)