# Importing Required Libraries
import pandas as pd
import numpy as np
from flask import Flask, request, render_template, redirect, url_for
import pickle
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Initializing Flask application
app = Flask(__name__, template_folder='templates')

# Depickling the both machine learning models 
model = pickle.load(open('model.pkl', 'rb'))
suggestmodel = pickle.load(open('suggestmodel.pkl', 'rb'))

# Configuring and Creating Database for this application
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# configuring Secret key for the application
app.config['SECRET_KEY'] = 'password'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initializing Bootstrap to the application
bootstrap = Bootstrap(app)

# Connecting Database to this application 
db = SQLAlchemy(app)

# Initializing Login Manager and Connecting to this application 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Creating User Class
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

# Defining the Load_User function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Creating LoginForm Class
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

# Creating RegisterForm Class
class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

# Application starts from here i.e "index.html"
@app.route('/')
def index():
    return render_template('index.html')

# Implementation of Login method
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return redirect(url_for('loginerrmsg'))
       
    return render_template('login.html', form=form)

# Implementation of SignUp method
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('signupmsg'))
        

    return render_template('signup.html', form=form)

# Function to Display Login Error Message
@app.route('/loginerrmsg')
def loginerrmsg():
    return render_template('loginerrmsg.html')

# Function to Display SignUp Successful Message
@app.route('/signupmsg')
def signupmsg():
    return render_template('signupmsg.html')

# Function to display Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    #if g.user:
        #return render_template('dashboard.html', user=session('user'))
    #name=current_user.username
    return render_template('dashboard.html', name=current_user.username)

# Function to display Dataset
@app.route('/dataset')
@login_required
def dataset():
    a = pd.read_csv("heart.csv") 
    a.to_html("Table.html") 
    return render_template('dataset.html')

# Function to display Prediction
@app.route('/userinput')
@login_required
def userinput():
    return render_template('userinput.html')

# Function to Predict the chance of getting Heart disease of a user
@app.route('/predict',methods=['POST'])
def predict():
    '''
    For rendering results on HTML GUI
    '''
    int_features = [float(x) for x in request.form.values()]
    final_features = [np.array(int_features)]
    prediction = model.predict(final_features)
    output = round(prediction[0], 2)
    if output==0:
        op="NO"
    else:
        op="YES"

    return render_template('userinput.html', prediction_text="The chance of getting Heart Disease is = {}".format(op))

# Function to display Analytics
@app.route('/graphs')
@login_required
def graphs():
    return render_template('graphs.html')

# Function to display EDA
@app.route('/display')
@login_required
def display():
    return render_template('display.html')

# Function to display No.of Humans beings deaths across the globe due to heart failures
@app.route('/visuval')
@login_required
def visuval():
    return render_template('visuval.html')

# Function to display Detection of type of Heart disease
@app.route('/detect')
@login_required
def detect():
    return render_template('detect.html')

# Function to Detect the type of Heart disease by taking symptoms from user
@app.route('/detection',methods=['POST'])
def detection():
    '''
    For rendering results on HTML GUI
    '''
    int_features = [int(x) for x in request.form.values()]
    final_features = [np.array(int_features)]
    prediction = suggestmodel.predict(final_features)

    output = round(prediction[0], 2)
    if output==0:
        op="HEART ARRHYTHMIAS"
    elif output==1:
        op="CONGENITAL HEART DISEASE"
    elif output==2:
        op="CARDIOMYOPATHY"
    else:
        op="ENDOCARDIUM"

    return render_template('detect.html', prediction_text="The chance of getting type of Heart Disease is = {}".format(op))

# Function to display Literature of Heart disease
@app.route('/concept')
@login_required
def concept():
    return render_template('concept.html')

# Function to display Working of Heart
@app.route('/woh')
@login_required
def woh():
    return render_template('woh.html')

# Function to display Symptoms of Heart disease
@app.route('/symptoms')
@login_required
def symptoms():
    return render_template('symptoms.html')

# Function to display Causes of Heart disease
@app.route('/cause')
@login_required
def cause():
    return render_template('cause.html')

# Function to display Risk Factors and Complications of Heart Disease
@app.route('/rfc')
@login_required
def rfc():
    return render_template('rfc.html')

# Function to display Precautions
@app.route('/pre')
@login_required
def pre():
    return render_template('pre.html')

# Function to display Suggestions
@app.route('/sp')
@login_required
def sp():
    return render_template('sp.html')

# Function to display About Us
@app.route('/aboutus')
@login_required
def aboutus():
    return render_template('aboutus.html')

# Function for Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Main method here where Flask application server starts running
if __name__ == '__main__':
    # Configuring this application for AUTO RELOAD whenever the code changes 
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    # Enabling the Flask application for debugging and run the server
    app.run(debug=True)
# Thats it we ended up here
