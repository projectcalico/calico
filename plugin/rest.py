from flask import Flask, url_for
from flask import json
from flask import request
app = Flask(__name__)

@app.route('/')
def welcome():
    return 'Welcome'

#curl -H "Content-type: application/json" -X POST http://127.0.0.1:5000/upload -d '{"message":"Hello Data"}'
@app.route('/upload/<filename>', methods=['POST'])
def upload(filename):
    if request.headers['Content-Type'] == 'application/json':
        # return "JSON Message: " + json.dumps(request.json)
        with open("/config.data/%s" % filename, 'wb') as f:
            f.write(request.data)
        return "Text Message: " + request.data

    else:
        resp = "Unsupported"
        resp.status_code = 415
        return resp

if __name__ == '__main__':
    app.run()