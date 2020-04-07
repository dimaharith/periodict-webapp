from flask import Flask, render_template, url_for, request, session, redirect, flash, Markup
from app import app
from flask import Flask
from flask import Flask, jsonify, request, make_response
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
from flask_login import LoginManager, current_user, login_user, login_required, logout_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from threading import Thread

app.config['JSON_SORT_KEYS'] = False
app.config['TESTING'] = False
app.config.from_pyfile('config.cfg')

mail = Mail(app)

s = URLSafeTimedSerializer('Thisisasecret!')
CONNECTION_STRING = "mongodb+srv://dima:berryjuice09@perio-cluster-80lad.mongodb.net/test?retryWrites=true&w=majority"
client = pymongo.MongoClient(CONNECTION_STRING)
db = client.get_database('perio-test')
assessments = db.assessments
users = db.users
patients = db.patients

class User:
    def __init__(self, email, fullname):
        self.email = email
        self.fullname = fullname

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.email

    @staticmethod
    def check_password(password_hash, password):
        return check_password_hash(password_hash, password)

login_manager = LoginManager(app)
@login_manager.user_loader
def load_user(email):
    u = db.users.find_one({"email": email})
    if not u:
        return None
    return User(email=u['email'], fullname=u['fullname'])

login_manager.init_app(app)
login_manager.login_view = 'index'


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, sender, recipients, body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.html = body
    Thread(target=send_async_email, args=(app, msg)).start()

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

class ResetForm(FlaskForm):
    newPassword = PasswordField('New Password', validators=[InputRequired()])
    confirmPassword = PasswordField('Confirm Password', validators=[InputRequired()])

class ForgotForm(FlaskForm):
    email = StringField('E-mail', validators=[InputRequired()])

class searchForm(FlaskForm):
    search = StringField('First name or last name', validators=[InputRequired()])

class timelineForm(FlaskForm):
    imgt0 = FileField('Before applying orthodontic appliance (T0)',validators=[ FileRequired(), FileAllowed(['jpg', 'png','jpeg','JPG','JPEG','PNG'], 'Images only!')])
    imgt1 = FileField('One week after application (T1)',validators=[ FileRequired(), FileAllowed(['jpg', 'png','jpeg','JPG','JPEG','PNG'], 'Images only!')])
    imgt2 = FileField('Four weeks after application (T2)',validators=[ FileRequired(), FileAllowed(['jpg', 'png','jpeg','JPG','JPEG','PNG'], 'Images only!')])

class diagnosisForm(FlaskForm):
    img = FileField('Choose an image',validators=[ FileRequired(), FileAllowed(['jpg', 'png','jpeg','JPG','JPEG','PNG'], 'Images only!')])

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, post-check=0, pre-check=0"
    return response

@app.route('/')
@app.route('/index', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard', offset=0))
    pageType='index'
    form = LoginForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            user = db.users.find_one({"email": form.email.data})
            if user and user['confirmed'] == 'true' and bcrypt.hashpw(request.form['password'].encode('utf-8'), user['password']) == user['password']:
                user_obj = User(email=user['email'], fullname=user['fullname'])
                login_user(user_obj)
                next_page = request.args.get('next')
                if not next_page or url_parse(next_page).netloc != '':
                    next_page = url_for('dashboard', offset=0)
                return redirect(next_page)

            elif user['confirmed'] == 'false':
                flash(Markup('Your account has not been verified yet. Please verify your account by clicking on the link sent to your e-mail or resend the link by clicking <a href="/resend_link/{}" class="alert-link">here</a>'.format(user['email'])),'error')
            else:
                flash(u'Incorrect email/password','error')

    return render_template('index.html', pageType=pageType, form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET','POST'])
def register():
    pageType = 'register'
    form = RegisterForm()

    if request.method == 'POST' and form.validate_on_submit():
        p_user = users.find_one({'email': request.form['email']})

        if p_user:
            flash('An account with this email already exists','error')
            return redirect(url_for('register'))
        elif request.form['password']!=request.form['confirmPassword']:
            flash('Passwords do not match','error')
            return redirect(url_for('register'))
        else:
            hashpass = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
            url = 'http://127.0.0.1:5000/users'
            users.insert({'email' : request.form['email'], 'password' : hashpass, 'fullname': request.form['fullname'], 'confirmed': False})
            user_obj = User(email=request.form['email'], fullname=request.form['fullname'])

            email = request.form['email']
            token = s.dumps(email, salt='email-confirm')

            #msg = Message('[PerioDict] Confirm Your E-mail', sender='periodictteam@gmail.com', recipients=[email])

            link = url_for('cseonfirm_email', token=token, _external=True)

            msg = '<p> Dear {}, </p> <p> Thanks for signing up for PerioDict! </p> <b> To verify your account, please click on this link (or paste it into your web browser): <br></b> {} <br> Thanks! <br> The PerioDict Team'.format(request.form['fullname'], link)

            #mail.send(msg)
            send_email('[PerioDict] Confirm Your E-mail', 'periodictteam@gmail.com', [email], msg)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('index')
            flash(u'A verification e-mail has been sent to your e-mail address: {}. Please verify your account to proceed.'.format(email), 'success')
            return redirect(next_page)

    return render_template('register.html', pageType=pageType, form=form)

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        flash(Markup('Your verification token has expired, please click <a href="/resend_link/{}" class="alert-link">here</a> to resend the verification link.'.format(email)), 'error')
        return redirect(url_for('index'))
    toUpdate = { "email": email }
    newValues = { "$set": {'confirmed': True}}
    users.update_one(toUpdate, newValues)
    flash(u'Your e-mail address, {}, has been successfully verified. You may now login to get started!'.format(email), 'success')
    return redirect(url_for('index'))

@app.route('/resend_link/<email>', methods=['GET'])
def resend_link(email):
    thisEmail = email
    token = s.dumps(thisEmail, salt='email-confirm')
    msg = Message('[PerioDict] Confirm Your E-mail', sender='periodictteam@gmail.com', recipients=[thisEmail])
    link = url_for('confirm_email', token=token, _external=True)
    msg.html = '<p> Dear {}, </p> <p> Thanks for signing up for PerioDict! </p> <b> To verify your account, please click on this link (or paste it into your web browser):</b> <br> {} <br> Thanks! <br> The PerioDict Team'.format(email, link)
    mail.send(msg)
    flash(u'A link has been sent to your e-mail address: {}'.format(email), 'success')
    return redirect(url_for('index'))

@app.route('/forgotpassword', methods=['GET','POST'])
def forgotpassword():
    form = ForgotForm()
    pageType = 'forgotpassword'

    if request.method == "GET":
        return render_template('forgotpassword.html', pageType=pageType, form=form)

    if request.method == "POST":
        login_user = users.find_one({'email': request.form['email']})
        if login_user:
            email = request.form['email']
            token = s.dumps(email, salt='password-reset')
            link = url_for('resetpassword', email=email, token=token, _external=True)
            msg = '<p> Dear {}, </p> <b> To reset your password, please click on this link (or paste it into your web browser): <br></b> {} <p>If you have not requested a password reset simply ignore this message.</p> <br> Thanks! <br> The PerioDict Team'.format(login_user['fullname'], link)
            send_email('[PerioDict] Password Reset', 'periodictteam@gmail.com', [email], msg)
            flash(u'A link to reset your password has been sent to your e-mail: {}'.format(email),'success')
            return redirect(url_for('index'))
        else:
            flash("We can't find your e-mail address. Are you sure you entered the correct e-mail address?",'error')
            return redirect(url_for('forgotpassword'))

    return render_template('forgotpassword.html', pageType=pageType, form=form)

@app.route('/resetpassword/<token>', methods=['GET','POST'])
def resetpassword(token):
    form = ResetForm()
    pageType = 'resetpassword'
    if request.method == "GET":
        try:
            email = s.loads(token, salt='password-reset', max_age=3600)
        except SignatureExpired:
            flash(u'The password reset token has expired. Please request another password reset.', 'error')
            return redirect(url_for('index'))
        return render_template('resetpassword.html', pageType=pageType, form=form, senttoken=token)

    if request.method == "POST":
        if request.form['newPassword'] == request.form['confirmPassword']:
            
            try:
                email = s.loads(token, salt='password-reset', max_age=3600)
            except SignatureExpired:
                flash(u'The password reset token has expired. Please request another password reset.', 'error')
                return redirect(url_for('index'))
            hashpass = bcrypt.hashpw(request.form['newPassword'].encode('utf-8'), bcrypt.gensalt())
            toUpdate = {'email': email}
            updatedUser = { "$set": {'password': hashpass}}
            users.update_one(toUpdate, updatedUser)
            flash(u'Successfully changed password for {}'.format(email), 'success')
            return redirect(url_for('index'))
        else:
            flash('Passwords do not match','error')
            return redirect(url_for('resetpassword', pageType=pageType, form=form, senttoken=token))


@app.route('/dashboard/<offset>', methods=['GET','POST'])
@login_required
def dashboard(offset):
    pageType = 'dashboard'
    if request.method == "GET":
        count = patients.find({'dentistemail': current_user.email}).count()
        if count != 0:
            url = 'http://127.0.0.1:5000/patients/'+current_user.email+'/'+offset
            patientList = requests.get(url).json()
            nextOffset = patientList['next_url'] 
            prevOffset = patientList['prev_url'] 
            showPrev = patientList['showPrev']
            showNext = patientList['showNext']

            resp = make_response(render_template('dashboard.html', showPrev=showPrev, showNext=showNext, prevOffset=prevOffset, nextOffset=nextOffset, pageType=pageType, patients=patientList['result'], offset=int(offset)))
            resp.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0') 
            return resp
        else:
            return render_template('dashboard.html', pageType=pageType, patients=[])

    if request.method == "POST":
        if request.form['search'] != "":
            count = patients.find({"$and": [{"dentistemail": current_user.email}, {"$or": [{"firstname": re.compile(request.form['search'], re.IGNORECASE)}, {"lastname": re.compile(request.form['search'], re.IGNORECASE)}]}]}).count()
            if count != 0:
                url = 'http://127.0.0.1:5000/patientssearch/'+current_user.email+'/'+request.form['search']+'/'+offset
                SpatientList = requests.get(url).json()
                SnextOffset = SpatientList['next_url'] 
                SprevOffset = SpatientList['prev_url'] 
                SshowPrev = SpatientList['showPrev']
                SshowNext = SpatientList['showNext']

                resp = make_response(render_template('dashboard.html', showPrev=SshowPrev, showNext=SshowNext, prevOffset=SprevOffset, nextOffset=SnextOffset, pageType=pageType, patients=SpatientList['result'], offset=int(offset)))
                resp.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0') 
                return resp
            else:
                flash(u'No results found', 'warning')
                return redirect(url_for('dashboard', offset=0))
        else:
            return redirect(url_for('dashboard', offset=0))


@app.route('/addpatient',methods=['POST','GET'])
@login_required
def addpatient():
    pageType = 'addpatient'
    form = addForm()
    url = 'http://127.0.0.1:5000/postpatient'

    if request.method == "POST":
        q = patients.find_one({ "govID": request.form['govID'] })
        if q is None:
            orthoValue = dict(form.orthotype.choices).get(form.orthotype.data)
            genderValue = dict(form.gender.choices).get(form.gender.data)
            dobValue = form.dob.data.strftime('%Y-%m-%d')
            patient = {'govID': request.form['govID'], 'firstname': request.form['firstname'], 'lastname': request.form['lastname'], 'DOB': dobValue,
                               'Gender': genderValue, 'OrthoType': orthoValue, 'dentistemail': current_user.email}
            response = requests.post(url, json = patient)
            flash(u'Successfully added patient', 'success')
            render_template('addpatient.html', pageType=pageType, form=form)
        else:
            flash(u'A patient with this government ID already exists', 'error')
            render_template('addpatient.html', pageType=pageType, form=form)

            
    return render_template('addpatient.html', pageType=pageType, form=form)

@app.route('/deleteassessment/<govID>/<dID>',methods=['GET','POST'])
@login_required
def deleteassessment(govID, dID):
    delResult = assessments.delete_one({'_id': ObjectId(dID)})
    if delResult.deleted_count != 0:
        flash('Assessment deleted successfully','success')
        return redirect(url_for('patienthistory', govID=govID, offset=0))
    else:
        flash('Woops! Could not delete assessment...', 'error')
        return redirect(url_for('patienthistory', govID=govID, offset=0))

@app.route('/deletepatient/<govID>',methods=['GET','POST'])
@login_required
def deletepatient(govID):
    if request.form['govIDToConfirm'] == govID:
        govIDToDelete = govID
        toDelete = { "govID": govIDToDelete }
        delResult = patients.delete_one(toDelete)
        if delResult.deleted_count != 0:
            flash('Patient deleted successfully','success')
            return redirect(url_for('dashboard', offset=0))
    else:
        flash('Could not delete patient, please make sure the entered government ID is correct', 'error')
        return redirect(url_for('patientoverview',govID=govID))


@app.route('/updatepatient/<govID>',methods=['GET','POST'])
@login_required
def updatepatient(govID):
    pageType='updatepatient'
    form = editForm()
    url = 'http://127.0.0.1:5000/putpatient/'+govID
    q = patients.find_one({ "govID": govID })
    patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                               'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
    if request.method == "GET":
        return render_template('editpatient.html', pageType=pageType, form=form, patient=patient)
                        
    if request.method == "POST":
        orthoValue = request.form.get('orthoType')
        genderValue = dict(form.gender.choices).get(form.gender.data)
        dobValue = form.dob.data.strftime('%Y-%m-%d')
        patient = {'govID': request.form['govID'], 'firstname': request.form['firstname'], 'lastname': request.form['lastname'], 'DOB': dobValue,
                           'Gender': genderValue, 'OrthoType': orthoValue, 'dentistemail': current_user.email}
        resp = requests.put(url, json = patient)
        flash(u'Successfully applied changes', 'success')
        return render_template('editpatient.html', pageType=pageType, form=form, patient=patient)

   
@app.route('/myaccount', methods=['GET','POST'])
@login_required
def myaccount():
    pageType = 'myaccount'
    form = AccountForm()

    if request.method == "GET":
        return render_template('myaccount.html', pageType=pageType, form=form)
    
    if request.method == "POST":
        login_user = users.find_one({'email': current_user.email})
        toUpdate = {'email': current_user.email}

        if request.form['newPassword'] == "" or request.form['confirmPassword'] == "" :
            updatedUser = { "$set": {'fullname': request.form['fullname']}}
            users.update_one(toUpdate, updatedUser)
            current_user.fullname = request.form['fullname']
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
@login_required
def patientoverview(govID=None):
    pageType='patientoverview'
    timelineF = timelineForm()
    diagnosisF = diagnosisForm()
    backurl = request.headers.get("Referer")
    global offset
    offset = backurl.split('/')[4]
    q = patients.find_one({ "govID": govID })
    formattedDate = datetime.strptime(q['DOB'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
    patient = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': formattedDate,
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType']}
    return render_template('patientoverview.html', pageType=pageType, patient=patient, timelineForm = timelineF, diagnosisForm = diagnosisF, offset=offset)


@app.route('/diagnosis/<govID>',methods=['GET','POST'])
@app.route('/diagnosis/<govID>/<dID>',methods=['GET','POST'])
@login_required
def diagnosis(dID=None, govID=None):
    pageType='diagnosis'
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
        return redirect(url_for('diagnosis',dID=a_id, govID=govID))


@app.route('/timeline/<govID>',methods=['GET','POST'])
@app.route('/timeline/<govID>/<dID>',methods=['GET','POST'])
@login_required
def timeline(dID=None, govID=None):
    pageType='timeline'
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
@login_required
def patienthistory(govID, offset):
    pageType='patienthistory'
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

        return render_template('patienthistory.html', showPrev=showPrev, showNext=showNext, prevOffset=prevOffset, nextOffset=nextOffset, pageType=pageType, patient=patient, assessments=aList['result'])
    else:
        return render_template('patienthistory.html', pageType=pageType, patient=patient, assessments=[])


#==== API CODE ====
@app.route('/users', methods=['GET'])
def get_all_users():
    output = []

    for q in users.find():
        output.append({'email': q['email'], 'password': q['password'],
                       'fullname': q['fullname']})

    return jsonify({'result': output})


@app.route('/users/<email>', methods=['GET'])
def get_a_user(email):
    q = users.find_one({'email': email})

    if q:
        output = {'email': q['email'], 'password': q['password'],
                  'fullname': q['fullname']}
    else:
        output = 'No results found'

    return jsonify({'result': output})


@app.route('/users', methods=['POST'])
def add_user():
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
    q = patients.find_one({"$and": [{"govID": govID}, {"dentistemail": email}]})
    if q:
        output = {'govID': q['govID'], 'firstname': q['firstname'], 'lastname': q['lastname'], 'DOB': q['DOB'],
                           'Gender': q['Gender'], 'OrthoType': q['OrthoType'], 'dentistemail' : q['dentistemail']}
    else:
        output = 'No results found'

    return jsonify({'result': output})

@app.route('/findapatientbyname/<email>/<name>', methods=['GET'])
def get_a_patient_by_name(email, name):
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
    toUpdate = { "email": current_user.email }
    
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
    offset = int(offset)
    limit = 6
    count = assessments.find({'govID': govID}).count()

    starting_id = assessments.find().sort('_id', -1)
    last_id = starting_id[offset]['_id']
    assessmentsList = assessments.find({'_id' : {'$lte' : last_id}, 'govID': govID}).sort('_id', -1).limit(limit)
    
    output = []

    for a in assessmentsList:
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

    if offset+limit >= count or count == limit:
        showNext = 'no'
    else:
        showNext = 'yes'

    next_url = '/assessments/'+govID+'/'+str(offset+limit)  
    prev_url =  '/assessments/'+govID+'/'+str(offset-limit)  
    return jsonify({'showPrev': showPrev, 'showNext': showNext, 'prev_url':str(offset-limit), 'next_url': str(offset+limit), 'result' : sortedAssessments})


@app.route('/patients/<email>/<offset>', methods=['GET'])
def paginate_patients(email, offset):
    offset = int(offset)
    limit = 10
    count = patients.find({'dentistemail': email}).count()

    starting_id = patients.find().sort('_id', -1)
    last_id = starting_id[offset]['_id']
    patientList = patients.find({'_id' : {'$lte' : last_id}, 'dentistemail': email}).sort('_id', -1).limit(limit)
    
    output = []

    for a in patientList:
        formattedDate = datetime.strptime(a['DOB'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
        a = ({'_id': a['_id'], 
                'govID': a['govID'],
                'firstname': a['firstname'],
                'lastname': a['lastname'],
                'DOB': formattedDate, 
                'Gender': a['Gender'],
                'OrthoType': a['OrthoType'],
                })
        
        jsonA = json.loads(json_util.dumps(a))
        output.append(jsonA)

    #sortedPatients = sorted(output,key=lambda x: x['firstname'])

    if offset-limit < 0:
        showPrev = 'no'
    else:
        showPrev = 'yes'

    if offset+limit >= count or count == limit:
        showNext = 'no'
    else:
        showNext = 'yes'

    next_url = '/patients/'+str(offset+limit)  
    prev_url =  '/patients/'+str(offset-limit)  
    return jsonify({'showPrev': showPrev, 'showNext': showNext, 'prev_url':str(offset-limit), 'next_url': str(offset+limit), 'result' : output})

@app.route('/patientssearch/<email>/<name>/<offset>', methods=['GET'])
def search_patients(email, name, offset):
    offset = int(offset)
    limit = 10

    starting_id = patients.find().sort('_id', -1)
    last_id = starting_id[offset]['_id']
    count = patients.find({"$and": [{"dentistemail": email}, {'_id' : {'$lte' : last_id}}, {"$or": [{"firstname": re.compile(name, re.IGNORECASE)}, {"lastname": re.compile(name, re.IGNORECASE)}]}]}).count()
    patientList = patients.find({"$and": [{"dentistemail": email}, {'_id' : {'$lte' : last_id}}, {"$or": [{"firstname": re.compile(name, re.IGNORECASE)}, {"lastname": re.compile(name, re.IGNORECASE)}]}]}).sort('_id', -1).limit(limit)
    
    output = []

    for a in patientList:
        formattedDate = datetime.strptime(a['DOB'], '%Y-%m-%d').date().strftime('%m/%d/%Y')
        a = ({'_id': a['_id'], 
                'govID': a['govID'],
                'firstname': a['firstname'],
                'lastname': a['lastname'],
                'DOB': formattedDate, 
                'Gender': a['Gender'],
                'OrthoType': a['OrthoType'],
                })
        
        jsonA = json.loads(json_util.dumps(a))
        output.append(jsonA)


    if offset-limit < 0:
        showPrev = 'no'
    else:
        showPrev = 'yes'

    if offset+limit > count or count == limit:
        showNext = 'no'
    else:
        showNext = 'yes'

    next_url = '/patients/'+str(offset+limit)  
    prev_url =  '/patients/'+str(offset-limit)  
    return jsonify({'count':count, 'showPrev': showPrev,  'showNext': showNext, 'prev_url':str(offset-limit), 'next_url': str(offset+limit), 'result' : output})