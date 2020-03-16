from flask import Flask, render_template, url_for, request, session, redirect, flash
from app import app
from flask import Flask
from flask import Flask, jsonify, request
from flask_pymongo import pymongo
from flask_restful import Resource, Api
from flask_cors import CORS
from flask_wtf import FlaskForm
from datetime import datetime
from wtforms.fields.html5 import DateField
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, FileField, BooleanField, RadioField, SelectField
from wtforms.validators import InputRequired, NumberRange, DataRequired
from flask_wtf.file import FileField, FileAllowed, FileRequired
import requests
import sys
import bcrypt
from bson import json_util, ObjectId
import json
import re



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
    dob = DateField('Date of Birth', format='%Y-%m-%d')
    gender = RadioField('Gender', default='femaleOpt', choices=[('femaleOpt', 'Female'), ('maleOpt', 'Male')])
    orthotype = SelectField('Type of Orthodontic Appliance', choices=[('none', 'No orthodontic appliance'), ('clear', 'Clear aligners (i.e. Invisalign)'), ('fixed', 'Fixed appliance')])

class AccountForm(FlaskForm):
    #email = StringField('E-mail')
    fullname = StringField('Full Name')
    currPassword = PasswordField('Current Password')
    newPassword = PasswordField('New Password')
    confirmPassword = PasswordField('Confirm Password')

class RegisterForm(FlaskForm):
    email = StringField('E-mail', validators=[InputRequired()])
    fullname = StringField('Full Name',validators=[InputRequired()] )
    password = PasswordField('Password', validators=[InputRequired()])
    confirmPassword = PasswordField('Confirm Password', validators=[InputRequired()])

class ForgotForm(FlaskForm):
    email = StringField('E-mail', validators=[InputRequired()])

class timelineForm(FlaskForm):
    imgt0 = FileField('Before applying orthodontic appliance (T0)',validators=[ FileRequired(), FileAllowed(['jpg', 'png','jpeg','JPG','JPEG','PNG'], 'Images only!')])
    imgt1 = FileField('One week after application (T1)',validators=[ FileRequired(), FileAllowed(['jpg', 'png','jpeg','JPG','JPEG','PNG'], 'Images only!')])
    imgt2 = FileField('Four weeks after application (T2)',validators=[ FileRequired(), FileAllowed(['jpg', 'png','jpeg','JPG','JPEG','PNG'], 'Images only!')])

class diagnosisForm(FlaskForm):
    img = FileField('Choose an image',validators=[ FileRequired(), FileAllowed(['jpg', 'png','jpeg','JPG','JPEG','PNG'], 'Images only!')])

@app.route('/')
@app.route('/index', methods=['GET','POST'])
def index():
    pageType = 'index'
    form = LoginForm()

    if request.method == 'POST' and form.validate_on_submit():
        users = db.users
        login_user = users.find_one({'email': request.form['email']})

        if login_user and bcrypt.hashpw(request.form['password'].encode('utf-8'), login_user['password']) == login_user['password']:
            session['user'] = request.form['email']
            session['fullname'] = login_user['fullname']
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect email/password')
            return redirect(url_for('index'))

    return render_template('index.html', pageType=pageType, form=form)

@app.route('/register', methods=['GET','POST'])
def register():
    pageType = 'register'
    form = RegisterForm()

    if request.method == 'POST' and form.validate_on_submit():
        users = db.users
        login_user = users.find_one({'email': request.form['email']})

        if login_user:
            flash('An account with this email already exists','error')
            return redirect(url_for('register'))
        elif request.form['password']!=request.form['confirmPassword']:
            flash('Passwords do not match','error')
            return redirect(url_for('register'))
        else:
            hashpass = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
            url = 'http://127.0.0.1:5000/users'
            users.insert({'email' : request.form['email'], 'password' : hashpass, 'fullname': request.form['fullname']})
            session['user'] = request.form['email']
            session['fullname'] = request.form['fullname']
            return redirect(url_for('dashboard'))

    return render_template('register.html', pageType=pageType, form=form)

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
    patients = db.patients

    if request.method == "POST":
        q = patients.find_one({ "govID": request.form['govID'] })
        if q is None:
            orthoValue = dict(form.orthotype.choices).get(form.orthotype.data)
            genderValue = dict(form.gender.choices).get(form.gender.data)
            dobValue = form.dob.data.strftime('%Y-%m-%d')
            patient = {'govID': request.form['govID'], 'firstname': request.form['firstname'], 'lastname': request.form['lastname'], 'DOB': dobValue,
                               'Gender': genderValue, 'OrthoType': orthoValue, 'dentistemail': session['user']}
            resp = requests.post(url, json = patient)
            flash(u'Successfully added patient', 'success')
            return render_template('addpatient.html', pageType=pageType, form=form)
        else:
            flash(u'A patient with this government ID already exists', 'error')
            return render_template('addpatient.html', pageType=pageType, form=form)

    return render_template('addpatient.html', pageType=pageType, form=form)

@app.route('/deletepatient/<govID>',methods=['GET','POST'])
def deletepatient(govID):
    patients = db.patients

    if request.form['govIDToConfirm'] == govID:
        govIDToDelete = govID
        toDelete = { "govID": govIDToDelete }
        delResult = patients.delete_one(toDelete)
        if delResult.deleted_count != 0:
            flash('Patient deleted successfully','success')
            return redirect(url_for('dashboard'))
    else:
        flash('Could not delete patient, please make sure the entered government ID is correct', 'error')
        return redirect(url_for('patientoverview',govID=govID))


@app.route('/updatepatient/<govID>',methods=['GET','POST'])
def updatepatient(govID):
    pageType='updatepatient'
    form = editForm()
    patients = db.patients
    url = 'http://127.0.0.1:5000/putpatient/'+govID
    q = patients.find_one({ "govID": govID })
    patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                               'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
    if request.method == "GET":
        return render_template('editpatient.html', pageType=pageType, form=form, patient=patient)
                        
    if request.method == "POST":
        orthoValue = request.form.get('orthoType')
        #orthoValue = dict(form.orthotype.choices).get(form.orthotype.data)
        genderValue = dict(form.gender.choices).get(form.gender.data)
        dobValue = form.dob.data.strftime('%Y-%m-%d')
        patient = {'govID': request.form['govID'], 'firstname': request.form['firstname'], 'lastname': request.form['lastname'], 'DOB': dobValue,
                           'Gender': genderValue, 'OrthoType': orthoValue, 'dentistemail': session['user']}
        resp = requests.put(url, json = patient)
        flash(u'Successfully applied changes', 'success')
        return render_template('editpatient.html', pageType=pageType, form=form, patient=patient)

   
@app.route('/myaccount', methods=['GET','POST'])
def myaccount():
    pageType = 'myaccount'
    form = AccountForm()
    backurl = request.headers.get("Referer")
    referrer = backurl.split('/')[3]
    users = db.users

    if request.method == "GET":
        return render_template('myaccount.html', pageType=pageType, form=form, loggedEmail=session['user'], referrer=referrer)
    
    if request.method == "POST":
        login_user = users.find_one({'email': session['user']})
        toUpdate = {'email': session['user']}

        if request.form['newPassword'] == "" or request.form['confirmPassword'] == "" :
            updatedUser = { "$set": {'fullname': request.form['fullname']}}
            users.update_one(toUpdate, updatedUser)
            session['fullname'] = request.form['fullname']
            flash(u'Successfully changed full name', 'success')
            return redirect(url_for('myaccount'))
        else:
            if bcrypt.hashpw(request.form['currPassword'].encode('utf-8'), login_user['password']) == login_user['password']:
                if request.form['newPassword']==request.form['confirmPassword']:
                    hashpass = bcrypt.hashpw(request.form['newPassword'].encode('utf-8'), bcrypt.gensalt())
                    updatedUser = { "$set": {'fullname': request.form['fullname'], 'password': hashpass}}
                    users.update_one(toUpdate, updatedUser)
                    flash(u'Successfully applied changes', 'success')
                    return redirect(url_for('myaccount'))
                else:
                    flash('Passwords do not match','error')
                    return redirect(url_for('myaccount'))
            else:
                flash('Current password is incorrect','error')
                return redirect(url_for('myaccount'))


@app.route('/patientoverview')
@app.route('/patientoverview/<govID>', methods=['GET', 'POST'])
def patientoverview(govID=None):
    pageType='patientoverview'
    patients = db.patients
    timelineF = timelineForm()
    diagnosisF = diagnosisForm()
    q = patients.find_one({ "govID": govID })
    formattedDate = datetime.strptime(q['DOB'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
    patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': formattedDate,
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
    return render_template('patientoverview.html', pageType=pageType, patient=patient, loggedEmail = session['user'], timelineForm = timelineF, diagnosisForm = diagnosisF)


@app.route('/diagnosis/<govID>',methods=['GET','POST'])
@app.route('/diagnosis/<govID>/<dID>',methods=['GET','POST'])
def diagnosis(dID=None, govID=None):
    pageType='diagnosis'
    assessments = db.assessments
    patients = db.patients
    q = patients.find_one({'govID': govID })
    backurl = request.headers.get("Referer")
    referrer = backurl.split('/')[3]
   
    formattedDate = datetime.today().strftime('%Y-%m-%d')

    if request.method == "GET":
        oid = dID
        dx = assessments.find_one({'_id': ObjectId(oid)})
        q = patients.find_one({'govID':dx['govID'] })
        formattedDate = datetime.strptime(q['DOB'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
        patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': formattedDate,
                               'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
        formattedDate = datetime.strptime(dx['date'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
        assessment = {
            'govID': dx['govID'],
            'date': formattedDate, 
            'type': dx['type'],
            'info': {
            'diagnosis' : dx['info']['diagnosis'],
            'severity' : dx['info']['severity'],
            'CF':
                {
                dx['info']['CF']['F1'],
                dx['info']['CF']['F2'],
                dx['info']['CF']['F3'],
                },
            'plaque': dx['info']['plaque'],
            'img' : dx['info']['img']
            }}
        #diagnosis = json.loads(json_util.dumps(assessment))
        return render_template('diagnosis.html', pageType=pageType, assessment = assessment, patient=patient, referrer=referrer)
   
    if request.method == "POST":
        new_a = {'govID': govID,
            'date': formattedDate, 
            'type': 'Periodontal disease diagnosis',
            'info': {
                'diagnosis' : 'Positive',
                'severity' : 'Mild',
                'CF':
                    {
                    'F1' : 't0 f1',
                    'F2' : 't0 f2',
                    'F3' : 't0 f3',
                    },
                'plaque': 'plaque t0',
                'img' : request.form['img']
                }}

        a_id = assessments.insert(new_a)
        #new_a = assessments.find_one({'_id': a_id})
        return redirect(url_for('diagnosis',dID=a_id, govID=govID))


@app.route('/timeline/<govID>',methods=['GET','POST'])
@app.route('/timeline/<govID>/<dID>',methods=['GET','POST'])
def timeline(dID=None, govID=None):
    pageType='timeline'
    assessments = db.assessments
    backurl = request.headers.get("Referer")
    referrer = backurl.split('/')[3]
    
    formattedDate = datetime.today().strftime('%Y-%m-%d')
    if request.method == "POST":
        new_a = {'govID': govID,
            'date': formattedDate, 
            'type': 'Comparative timeline and analysis',
            'info': [{
                'diagnosis' : 'Positive',
                'severity' : 'Mild',
                'CF':
                    {
                    'F1' : 't0 f1',
                    'F2' : 't0 f2',
                    'F3' : 't0 f3',
                    },
                'plaque': 'plaque t0',
                'img' : request.form['imgt0']
                },
                 {
                'diagnosis' : 'Positive',
                'severity' : 'Moderate',
                'CF':
                    {
                   'F1' : 't1 f1',
                    'F2': 't1 f2',
                    'F3' : 't1 f3',
                    },
                'plaque': 'plaque t1',
            'img' : request.form['imgt1']
            },
             {
                'diagnosis' : 'Positive',
                'severity' : 'Severe',
            'CF':
                    {
                   'F1' :   't2 f1',
                   'F2' : 't2 f2',
                   'F3' : 't2 f3',
                    },
            'plaque': 'plaque t2',
            'img' : request.form['imgt2']
            }],
            'comment' : 'yo patient sucks'
            }

        #json_a = jsonify(new_a)
        a_id = assessments.insert(new_a)
        #new_a = assessments.find_one({'_id': a_id})
        return redirect(url_for('timeline',dID=a_id, govID=govID))
    if request.method == "GET":
        oid = dID
        dx = assessments.find_one({'_id': ObjectId(oid)})
        patients = db.patients
        q = patients.find_one({'govID': govID })
        formattedDate = datetime.strptime(q['DOB'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
        patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': formattedDate,
                               'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
        formattedDate = datetime.strptime(dx['date'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
        comment = dx['comment']
        assessment = [{
                'diagnosis' : dx['info'][0]['diagnosis'],
                'severity' : dx['info'][0]['severity'],
                'CF':
                    {
                    dx['info'][0]['CF']['F1'],
                    dx['info'][0]['CF']['F2'],
                    dx['info'][0]['CF']['F3'],
                    },
                'plaque': dx['info'][0]['plaque'],
                'img' : dx['info'][0]['img']
                },
                 {
                'diagnosis' : dx['info'][1]['diagnosis'],
                'severity' : dx['info'][1]['severity'],
                'CF':
                {
                dx['info'][1]['CF']['F1'],
                dx['info'][1]['CF']['F2'],
                dx['info'][1]['CF']['F3'],
                },
            'plaque': dx['info'][1]['plaque'],
            'img' : dx['info'][1]['img']
            },
             {
            'diagnosis' : dx['info'][2]['diagnosis'],
            'severity' : dx['info'][2]['severity'],
            'CF':
                {
                dx['info'][2]['CF']['F1'],
                dx['info'][2]['CF']['F2'],
                dx['info'][2]['CF']['F3'],
                },
            'plaque': dx['info'][2]['plaque'],
            'img' : dx['info'][2]['img']
            }]
        return render_template('timeline.html', pageType=pageType, assessments = assessment, patient=patient, comment=comment, referrer=referrer)


@app.route('/patienthistory/<govID>/<offset>', methods=['GET'])
def patienthistory(govID, offset):
    pageType='patienthistory'
    patients = db.patients
    assessments = db.assessments
    q = patients.find_one({ "govID": govID }) 
    formattedDate = datetime.strptime(q['DOB'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
    patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': formattedDate,
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
    
    count = assessments.find({'govID': govID}).count()
    if count != 0:
        url = 'http://127.0.0.1:5000/assessments/'+govID+'/'+offset
        aList = requests.get(url).json()
        nextOffset = aList['next_url'] 
        prevOffset = aList['prev_url'] 
        showPrev = aList['showPrev']
        showNext = aList['showNext']
        '''
        sortedAssessments = sorted(
        aList['result'],
        key=lambda x: datetime.strptime(x['date'], '%m/%d/%Y'), reverse=True
        )
        '''
        return render_template('patienthistory.html', showPrev=showPrev, showNext=showNext, prevOffset=prevOffset, nextOffset=nextOffset, pageType=pageType, patient=patient, assessments=aList['result'], loggedEmail = session['user'])
    else:
        return render_template('patienthistory.html', pageType=pageType, patient=patient, assessments=[], loggedEmail = session['user'])
'''
@app.route('/patienthistory2/<govID>', methods=['GET'])
def patienthistory2(govID):
    pageType='patienthistory'
    patients = db.patients
    assessments = db.assessments
    q = patients.find_one({ "govID": govID }) 

    aList = []
    for a in assessments.find({ "govID": govID }):
        formattedDate = datetime.strptime(a['date'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
        if a['type'] == 'Periodontal disease diagnosis':
            a = ({'_id': a['_id'], 
                'govID': a['govID'],
                'date': formattedDate, 
                'type': a['type'],
                'info': {
                'diagnosis' : a['info']['diagnosis'],
                'severity' : a['info']['severity'],
                'CF':
                    {
                    a['info']['CF']['F1'],
                    a['info']['CF']['F2'],
                    a['info']['CF']['F3'],
                    },
                'plaque': a['info']['plaque']
                }})
            jsonA = json.loads(json_util.dumps(a))
            aList.append(jsonA)
        else:
            a = ({'_id': a['_id'], 
                'govID': a['govID'],
                'date': formattedDate, 
                'type': a['type'],
                'info': [
                {
                'diagnosis' : a['info'][0]['diagnosis'],
                'severity' : a['info'][0]['severity'],
                'CF':
                    {
                    a['info'][0]['CF']['F1'],
                    a['info'][0]['CF']['F2'],
                    a['info'][0]['CF']['F3'],
                    },
                'plaque': a['info'][0]['plaque']
                },
                 {
                'diagnosis' : a['info'][1]['diagnosis'],
                'severity' : a['info'][1]['severity'],
                'CF':
                    {
                    a['info'][1]['CF']['F1'],
                    a['info'][1]['CF']['F2'],
                    a['info'][1]['CF']['F3'],
                    },
                'plaque': a['info'][1]['plaque']
                },
                 {
                'diagnosis' : a['info'][2]['diagnosis'],
                'severity' : a['info'][2]['severity'],
                'CF':
                    {
                    a['info'][2]['CF']['F1'],
                    a['info'][2]['CF']['F2'],
                    a['info'][2]['CF']['F3'],
                    },
                'plaque': a['info'][2]['plaque']
                }
                ]})

            jsonA = json.loads(json_util.dumps(a))
            aList.append(jsonA)

    sortedAssessments = sorted(
    aList,
    key=lambda x: datetime.strptime(x['date'], '%m/%d/%Y'), reverse=True
    )

    formattedDate = datetime.strptime(q['DOB'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
    patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': formattedDate,
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType']}

    return render_template('patienthistory.html', pageType=pageType, patient=patient, assessments = sortedAssessments, loggedEmail = session['user'])
'''
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

#PUT/UPDATE a patient
@app.route('/putpatient/<govID>', methods=['PUT'])
def update_patient(govID):
    patients = db.patients
    #patient = request.json['govID']
    toUpdate = { "govID": govID }
    
    newGovID = request.json['govID']
    newFirstName = request.json['firstname']
    newLastName = request.json['lastname']
    newDOB = request.json['DOB']
    newGender = request.json['Gender']
    newOrthoType = request.json['OrthoType']
    newValues = { "$set": {'govID': newGovID, 'firstname': newFirstName, 'lastname': newLastName, 'DOB': newDOB,
                           'Gender': newGender, 'OrthoType': newOrthoType}}
    
    patients.update_one(toUpdate, newValues)
    return jsonify({'result': 'success'})

@app.route('/putuser', methods=['PUT'])
def update_user():
    users = db.users
    toUpdate = { "email": session['user'] }
    
    newGovID = request.json['govID']
    newFirstName = request.json['firstname']
    newLastName = request.json['lastname']
    newDOB = request.json['DOB']
    newGender = request.json['Gender']
    newOrthoType = request.json['OrthoType']
    newValues = { "$set": {'govID': newGovID, 'firstname': newFirstName, 'lastname': newLastName, 'DOB': newDOB,
                           'Gender': newGender, 'OrthoType': newOrthoType}}
    
    patients.update_one(toUpdate, newValues)
    return jsonify({'result': 'success'})

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

@app.route('/getassessments/<govID>', methods=['GET'])
def getassessments(govID):
    pageType='patienthistory'
    patients = db.patients
    assessments = db.assessments
    q = patients.find_one({ "govID": govID }) 

    aList = []
    for a in assessments.find({ "govID": govID }):
        formattedDate = datetime.strptime(a['date'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
        if a['type'] == 'Periodontal disease diagnosis':
            a = ({'_id': a['_id'], 
                'govID': a['govID'],
                'date': formattedDate, 
                'type': a['type'],
                'info': {
                'diagnosis' : a['info']['diagnosis'],
                'severity' : a['info']['severity'],
                'CF':
                    {
                    a['info']['CF']['F1'],
                    a['info']['CF']['F2'],
                    a['info']['CF']['F3'],
                    },
                'plaque': a['info']['plaque']
                }})
            jsonA = json.loads(json_util.dumps(a))
            aList.append(jsonA)
        else:
            a = ({'_id': a['_id'], 
                'govID': a['govID'],
                'date': formattedDate, 
                'type': a['type'],
                'info': [
                {
                'diagnosis' : a['info'][0]['diagnosis'],
                'severity' : a['info'][0]['severity'],
                'CF':
                    {
                    a['info'][0]['CF']['F1'],
                    a['info'][0]['CF']['F2'],
                    a['info'][0]['CF']['F3'],
                    },
                'plaque': a['info'][0]['plaque']
                },
                 {
                'diagnosis' : a['info'][1]['diagnosis'],
                'severity' : a['info'][1]['severity'],
                'CF':
                    {
                    a['info'][1]['CF']['F1'],
                    a['info'][1]['CF']['F2'],
                    a['info'][1]['CF']['F3'],
                    },
                'plaque': a['info'][1]['plaque']
                },
                 {
                'diagnosis' : a['info'][2]['diagnosis'],
                'severity' : a['info'][2]['severity'],
                'CF':
                    {
                    a['info'][2]['CF']['F1'],
                    a['info'][2]['CF']['F2'],
                    a['info'][2]['CF']['F3'],
                    },
                'plaque': a['info'][2]['plaque']
                }
                ]})

            jsonA = json.loads(json_util.dumps(a))
            aList.append(jsonA)

    sortedAssessments = sorted(
    aList,
    key=lambda x: datetime.strptime(x['date'], '%m/%d/%Y'), reverse=True
    )

    return jsonify({'result': sortedAssessments})

@app.route('/assessments/<govID>/<offset>', methods=['GET'])
def assessmentspag(govID, offset):
    assessments = db.assessments
    offset = int(offset)
    limit = 6
    count = assessments.find({'govID': govID}).count()

    starting_id = assessments.find().sort('_id', -1)
    last_id = starting_id[offset]['_id']
    assessments = assessments.find({'_id' : {'$lte' : last_id}, 'govID': govID}).sort('_id', -1).limit(limit)
    
    output = []

    for a in assessments:
        formattedDate = datetime.strptime(a['date'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
        if a['type'] == 'Periodontal disease diagnosis':
            a = ({'_id': a['_id'], 
                'govID': a['govID'],
                'date': formattedDate, 
                'type': a['type'],
                'info': {
                'diagnosis' : a['info']['diagnosis'],
                'severity' : a['info']['severity'],
                'CF':
                    {
                    a['info']['CF']['F1'],
                    a['info']['CF']['F2'],
                    a['info']['CF']['F3'],
                    },
                'plaque': a['info']['plaque']
                }})
        else:
            a = ({'_id': a['_id'], 
                'govID': a['govID'],
                'date': formattedDate, 
                'type': a['type'],
                'info': [
                {
                'diagnosis' : a['info'][0]['diagnosis'],
                'severity' : a['info'][0]['severity'],
                'CF':
                    {
                    a['info'][0]['CF']['F1'],
                    a['info'][0]['CF']['F2'],
                    a['info'][0]['CF']['F3'],
                    },
                'plaque': a['info'][0]['plaque']
                },
                 {
                'diagnosis' : a['info'][1]['diagnosis'],
                'severity' : a['info'][1]['severity'],
                'CF':
                    {
                    a['info'][1]['CF']['F1'],
                    a['info'][1]['CF']['F2'],
                    a['info'][1]['CF']['F3'],
                    },
                'plaque': a['info'][1]['plaque']
                },
                 {
                'diagnosis' : a['info'][2]['diagnosis'],
                'severity' : a['info'][2]['severity'],
                'CF':
                    {
                    a['info'][2]['CF']['F1'],
                    a['info'][2]['CF']['F2'],
                    a['info'][2]['CF']['F3'],
                    },
                'plaque': a['info'][2]['plaque']
                }
                ]})

        jsonA = json.loads(json_util.dumps(a))
        output.append(jsonA)

    sortedAssessments = sorted(
        output,
        key=lambda x: datetime.strptime(x['date'], '%m/%d/%Y'), reverse=True
        )

    if offset-limit < 0:
        showPrev = 'no'
    else:
        showPrev = 'yes'

    if offset+limit > count:
        showNext = 'no'
    else:
        showNext = 'yes'

    next_url = '/assessments/'+govID+'/'+str(offset+limit)  
    prev_url =  '/assessments/'+govID+'/'+str(offset-limit)  
    return jsonify({'showPrev': showPrev, 'showNext': showNext, 'prev_url':str(offset-limit), 'next_url': str(offset+limit), 'result' : sortedAssessments})
    