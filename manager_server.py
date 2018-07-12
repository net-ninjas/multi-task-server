from flask import Flask
from random import sample
from json import loads as decode, dumps as encode
from datetime import datetime
from socket import socket


app = Flask(__name__)

@app.route('/')
def root():
    return "Hello world"

app.run()

class Device(object):
    def __init__(self, devices=None):
        self.devices = devices or []
        #self.socket = socket(...)
        self.req_count = 0
        self.capabilities = []
        self.last_task_time = datetime.now()

