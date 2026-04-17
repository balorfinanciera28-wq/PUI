from flask import Flask, request, Response
import requests

app = Flask(__name__)

TARGET_URL = "http://192.168.10.250:8080/Git/Repository/Index"

@app.route('/', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE'])
@app.route('/<path:path>', methods=['GET','POST','PUT','DELETE'])
def proxy(path):

    url = f"{TARGET_URL}/{path}" if path else TARGET_URL

    headers = dict(request.headers)
    headers.pop('Host', None)

    resp = requests.request(
        method=request.method,
        url=url,
        headers=headers,
        data=request.get_data(),
        params=request.args
    )

    return Response(resp.content, resp.status_code, resp.headers.items())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)