from flask import Flask
from random import sample
from json import loads as decode, dumps as encode
from datetime import datetime
from socket import socket

class costumer(object):
    def __init__(self):
        self.devices = []
        self.req_count = 0

class client(object):
    def __init__(self, costumer):
        self.socket = socket(...)
        self.costumer = costumer
        self.req_count = 0
        self.capabilities = []
        self.last_task_time = datetime.now()