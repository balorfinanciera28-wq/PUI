from waitress import serve
from appsi import app, PORT

serve(app, host="localhost", port=PORT)