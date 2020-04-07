from flask import Flask
from config import Config
from flask_login import LoginManager, current_user, login_user, login_required
from flask_pymongo import pymongo
from .user import User
app = Flask(__name__)
app.config.from_object(Config)
app.config['MONGO_URI'] = "mongodb+srv://dima:berryjuice09@perio-cluster-80lad.mongodb.net/test?retryWrites=true&w=majority"
app.debug = True
'''
CONNECTION_STRING = "mongodb+srv://dima:berryjuice09@perio-cluster-80lad.mongodb.net/test?retryWrites=true&w=majority"
client = pymongo.MongoClient(CONNECTION_STRING)
db = client.get_database('perio-test')
'''
from app import routes

