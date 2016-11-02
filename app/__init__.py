from flask import Flask

app = Flask(__name__)
app.config.from_object('config') #Load the config from config.py
#set the secret key
app.secret_key = app.config['SECRET_KEY']

from app import views