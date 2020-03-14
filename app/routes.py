from flask import Flask, render_template, url_for, request, session, redirect, flash
from app import app
from flask import Flask
from flask import Flask, jsonify, request
from flask_pymongo import pymongo
from flask_restful import Resource, Api
from flask_cors import CORS
from flask_wtf import FlaskForm
import datetime
from wtforms.fields.html5 import DateField
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, FileField, BooleanField, RadioField, SelectField
from wtforms.validators import InputRequired, NumberRange, DataRequired
import requests
import sys



app.config['JSON_SORT_KEYS'] = False
CONNECTION_STRING = "mongodb+srv://dima:berryjuice09@perio-cluster-80lad.mongodb.net/test?retryWrites=true&w=majority"
client = pymongo.MongoClient(CONNECTION_STRING)
db = client.get_database('perio-test')

class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])


class addForm(FlaskForm):
    govID = StringField('Government ID', validators=[InputRequired()])
    firstname = StringField('First Name', validators=[InputRequired()])
    lastname = StringField('Last Name', validators=[InputRequired()])
    dob = DateField('Date of Birth', format='%Y-%m-%d', validators=[InputRequired()])
    gender = RadioField('Gender', default='femaleOpt', choices=[('femaleOpt', 'Female'), ('maleOpt', 'Male')], validators=[DataRequired()])
    orthotype = SelectField('Type of Orthodontic Appliance', choices=[('none', 'No orthodontic appliance'), ('clear', 'Clear aligners (i.e. Invisalign)'), ('fixed', 'Fixed appliance')], validators=[DataRequired()])

class editForm(FlaskForm):
    govID = StringField('Government ID')
    firstname = StringField('First Name')
    lastname = StringField('Last Name')
    dob = DateField('Date of Birth', format='%d-%m-%Y')
    gender = RadioField('Gender', default='femaleOpt', choices=[('femaleOpt', 'Female'), ('maleOpt', 'Male')])
    orthotype = SelectField('Type of Orthodontic Appliance', choices=[('none', 'No orthodontic appliance'), ('clear', 'Clear aligners (i.e. Invisalign)'), ('fixed', 'Fixed appliance')])

class AccountForm(FlaskForm):
    #email = StringField('E-mail')
    fullname = StringField('Full Name')
    password = PasswordField('Password')
    confirmPassword = PasswordField('Confirm Password')


class ForgotForm(FlaskForm):
    email = StringField('E-mail', validators=[InputRequired()])

@app.route('/')
@app.route('/index', methods=['GET','POST'])
def index():
    pageType = 'index'
    form = LoginForm()

    if request.method == 'POST':
        users = db.users
        login_user = users.find_one({'email': request.form['email']})

        if login_user:
            if request.form['password'] == login_user['password']:
                session['user'] = request.form['email']
                session['fullname'] = login_user['fullname']
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect email/password')
                return redirect(url_for('index'))

    return render_template('index.html', pageType=pageType, form=form)

@app.route('/logout')
def logout():
   # remove the username from the session if it is there
   session.pop('user', None)
   session.pop('fullname', None)
   return redirect(url_for('index'))

@app.route('/forgotpassword')
def forgotpassword():
    form = ForgotForm()
    pageType = 'forgotpassword'
    return render_template('forgotpassword.html', pageType=pageType, form=form)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    pageType = 'dashboard'
    patients = db.patients
    if 'user' in session:
        r = requests.get('http://127.0.0.1:5000/mypatients/'+session['user']).json()
        patientlist = r.get('result')
        return render_template('dashboard.html', pageType = pageType, patients=patientlist, fullname = session['fullname'], loggedEmail = session['user'])
    return 'You are not logged in!'

@app.route('/addpatient',methods=['POST','GET'])
def addpatient():
    pageType = 'addpatient'
    form = addForm()
    url = 'http://127.0.0.1:5000/postpatient'
                        
    if request.method == "POST":
        orthoValue = dict(form.orthotype.choices).get(form.orthotype.data)
        genderValue = dict(form.gender.choices).get(form.gender.data)
        dobValue = form.dob.data.strftime('%d-%m-%Y')
        patient = {'govID': request.form['govID'], 'firstname': request.form['firstname'], 'lastname': request.form['lastname'], 'DOB': dobValue,
                           'Gender': genderValue, 'OrthoType': orthoValue, 'dentistemail': session['user']}
        resp = requests.post(url, json = patient)
        flash(u'Successfully added patient to database', 'success')
        return render_template('addpatient.html', pageType=pageType, form=form)

    return render_template('addpatient.html', pageType=pageType, form=form)

@app.route('/updatepatient/<govID>')
def updatepatient(govID):
    form = PatientForm()
    pageType='updatepatient'
    patients = db.patients
    q = patients.find_one({ "govID": govID })
    patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
    return render_template('editpatient.html', pageType=pageType, form=form, patient=patient)
                        
    if request.method == "POST":
        q = patients.find_one({ "govID": govID })
        if q:
            patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
    return render_template('editpatient.html', pageType=pageType, form=form)

   
@app.route('/myaccount', methods=['GET','POST'])
def myaccount():
    pageType = 'myaccount'
    form = AccountForm()
    return render_template('myaccount.html', pageType=pageType, form=form, loggedEmail=session['admin'])

@app.route('/patientoverview')
@app.route('/patientoverview/<govID>', methods=['GET', 'POST'])
def patientoverview(govID=None):
    pageType='patientoverview'
    patients = db.patients

    q = patients.find_one({ "govID": govID })
    patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
    return render_template('patientoverview.html', pageType=pageType, patient=patient, loggedEmail = session['admin'])


@app.route('/diagnosis')
def diagnosis():
    pageType='diagnosis'
    return render_template('diagnosis.html', pageType=pageType)

@app.route('/timeline')
def timeline():
    pageType='timeline'
    return render_template('timeline.html', pageType=pageType)

@app.route('/patienthistory')
def patienthistory():
    pageType='patienthistory'
    return render_template('patienthistory.html', pageType=pageType)

#==== API CODE ====
@app.route('/users', methods=['GET'])
def get_all_users():
    users = db.users

    output = []

    for q in users.find():
        output.append({'email': q['email'], 'password': q['password'],
                       'fullname': q['fullname']})

    return jsonify({'result': output})


@app.route('/users/<email>', methods=['GET'])
def get_a_user(email):
    users = db.users

    q = users.find_one({'email': email})

    if q:
        output = {'email': q['email'], 'password': q['password'],
                  'fullname': q['fullname']}
    else:
        output = 'No results found'

    return jsonify({'result': output})


@app.route('/users', methods=['POST'])
def add_user():
    users = db.users

    email = request.json['email']
    password = request.json['password']
    fullname = request.json['fullname']

    user_id = users.insert({'email': email, 'password': password,
                            'fullname': fullname})
    new_user = users.find_one({'_id': user_id})

    output = {'email': new_user['email'], 'password': new_user['password'],
              'fullname': new_user['fullname']}

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
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType'], 'dentistemail' : q['dentistemail']})
    else:
        output = 'No results found'

    return jsonify({'result': output})

@app.route('/findapatientbyid/<email>/<govID>', methods=['GET'])
def get_a_patient_by_id(email, govID):
    patients = db.patients

    q = patients.find_one({"$and": [{"govID": govID}, {"dentistemail": email}]})
    if q:
        output = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType'], 'dentistemail' : q['dentistemail']}
    else:
        output = 'No results found'

    return jsonify({'result': output})

@app.route('/findapatientbyname/<email>/<name>', methods=['GET'])
def get_a_patient_by_name(email, name):
    patients = db.patients

    q = patients.find_one({"$and": [{"dentistemail": email}, {"$or": [{"firstname": re.compile(name, re.IGNORECASE)}, {"lastname": re.compile(name, re.IGNORECASE)}]}]})
    if q:
        output = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType'], 'dentistemail' : q['dentistemail']}
    else:
        output = 'No results found'

    return jsonify({'result': output})

@app.route('/postpatient', methods=['POST'])
def add_question():
    patients = db.patients

    govID = request.json['govID']
    firstname = request.json['firstname']
    lastname = request.json['lastname']
    DOB = request.json['DOB']
    Gender = request.json['Gender']
    OrthoType = request.json['OrthoType']
    dentistemail = request.json['dentistemail']

    p_id = patients.insert({
            "govID": request.json['govID'],
            "firstname": request.json['firstname'],
            "lastname": request.json['lastname'],
            "DOB": request.json['DOB'],
            "Gender": request.json['Gender'],
            "OrthoType": request.json['OrthoType'],
            "dentistemail": request.json['dentistemail']
        })
    new_p = patients.find_one({'_id': p_id})

    output = {
            "govID": new_p['govID'],
            "firstname": new_p['firstname'],
            "lastname": new_p['lastname'],
            "DOB": new_p['DOB'],
            "Gender": new_p['Gender'],
            "OrthoType": new_p['OrthoType'],
            "dentistemail": new_p['dentistemail']
        }

    return jsonify({'result': output})