from flask import render_template
from app import app

@app.route('/')
@app.route('/index')
def index():
    user = {'username': 'Miguel'}
    return render_template('index.html', title='Home', user=user)

@app.route('/forgotpassword')
def forgotpassword():
    return render_template('forgotpassword.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/addpatient')
def addpatient():
    return render_template('addpatient.html')

@app.route('/updatepatient')
def updatepatient():
    return render_template('editpatient.html')

@app.route('/myaccount')
def myaccount():
    return render_template('myaccount.html')

@app.route('/patientoverview')
def patientoverview():
    return render_template('patientoverview.html')

@app.route('/diagnosis')
def diagnosis():
    return render_template('diagnosis.html')

@app.route('/timeline')
def timeline():
    return render_template('timeline.html')

@app.route('/patienthistory')
def patienthistory():
    return render_template('patienthistory.html')