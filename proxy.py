# -*- coding: utf-8 -*-
#example: curl http://127.0.0.1:8080/http://www.google.com > ./index.html

from flask import Flask
from flask import Response
from flask import stream_with_context

import requests

app = Flask(__name__)


@app.route('/<path:url>')
def home(url):
    print("going to url:", url)
    req = requests.get(url, stream=True)
    return Response(stream_with_context(req.iter_content()), content_type=req.headers['content-type'])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
