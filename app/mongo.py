from flask import Flask, jsonify, request
from flask_pymongo import pymongo
import re
#import db


app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
CONNECTION_STRING = "mongodb+srv://dima:berryjuice09@perio-cluster-80lad.mongodb.net/test?retryWrites=true&w=majority"
client = pymongo.MongoClient(CONNECTION_STRING)

db = client.get_database('perio-test')

#USERS
@app.route('/users', methods=['GET'])
def get_all_users():
    users = db.users

    output = []

    for q in users.find():
        output.append({'email': q['email'], 'password': q['password'],
                       'firstname': q['firstname'], 'lastname': q['lastname']})

    return jsonify({'result': output})


@app.route('/users/<email>', methods=['GET'])
def get_a_user(email):
    users = db.users

    q = users.find_one({'email': email})

    if q:
        output = {'email': q['email'], 'password': q['password'],
                  'firstname': q['firstname'], 'lastname': q['lastname']}
    else:
        output = 'No results found'

    return jsonify({'result': output})


@app.route('/users', methods=['POST'])
def add_user():
    users = db.users

    email = request.json['email']
    password = request.json['password']
    firstname = request.json['firstname']
    lastname = request.json['lastname']

    user_id = users.insert({'email': email, 'password': password,
                            'firstname': firstname, 'lastname': lastname})
    new_user = users.find_one({'_id': user_id})

    output = {'email': new_user['email'], 'password': new_user['password'],
              'firstname': new_user['firstname'], 'lastname': new_user['lastname']}

    return jsonify({'result': output})

#PATIENTS

@app.route('/mypatients/<email>', methods=['GET'])
def get_all_patients(email):
    patients = db.patients

    output = []
    q = patients.find({'dentistemail': email})

    if q:
        for q in patients.find({'dentistemail': email}):
            output.append({'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                           'Gender': q['Gender'], 'Orthodontics': q['Orthodontics'], 'OrthoType': q['OrthoType']})
    else:
    	output = 'No results found'

    return jsonify({'result': output})

@app.route('/findapatientbyid/<email>/<govID>', methods=['GET'])
def get_a_patient_by_id(email, govID):
    patients = db.patients

    q = patients.find_one({"$and": [{"govID": int(govID)}, {"dentistemail": email}]})
    if q:
        output = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                           'Gender': q['Gender'], 'Orthodontics': q['Orthodontics'], 'OrthoType': q['OrthoType']}
    else:
        output = 'No results found'

    return jsonify({'result': output})

@app.route('/findapatientbyname/<email>/<name>', methods=['GET'])
def get_a_patient_by_name(email, name):
    patients = db.patients

    q = patients.find_one({"$and": [{"dentistemail": email}, {"$or": [{"firstname": re.compile(name, re.IGNORECASE)}, {"lastname": re.compile(name, re.IGNORECASE)}]}]})
    if q:
        output = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                           'Gender': q['Gender'], 'Orthodontics': q['Orthodontics'], 'OrthoType': q['OrthoType']}
    else:
        output = 'No results found'

    return jsonify({'result': output})

#Add a patient, delete a patient

if __name__ == '__main__':
    app.run(port=8000)
