from flask import Flask
import redis
import os
import json

app = Flask(__name__)
r_server = redis.Redis("localhost", decode_responses=True)
S3_BUCKET_NAME = os.environ['S3_BUCKET_NAME']
S3_KEY_PREFIX = '/image/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
app.secret_key = os.environ['APP_KEY']
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
numitem = 10
