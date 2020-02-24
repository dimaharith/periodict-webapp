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

@app.route('/addapatient')
def addapatient():
    return render_template('addapatient.html')

@app.route('/updatepatient')
def updatepatient():
    return render_template('editapatient.html')

@app.route('/myaccount')
def myaccount():
    return render_template('myaccount.html')