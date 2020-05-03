import plotly.graph_objects as go
import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, render_template, redirect, url_for
import pickle
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import matplotlib.pyplot as plt
import seaborn as sns
import os
import psycopg2



app = Flask(__name__, template_folder='templates')
model = pickle.load(open('model.pkl', 'rb'))
suggestmodel = pickle.load(open('suggestmodel.pkl', 'rb'))
#file_path = os.path.abspath(os.getcwd())+"\database.db"
#DATABASE_URL = sqlite:////Users/tadinadasatyasaikrishnapavan/Documents/FirstTrailPracticum/database.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'password'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<center><h1>Invalid username or password</h1></center>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<center><h1>New user has been created!</h1></center>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/dataset')
def dataset():
    a = pd.read_csv("heart.csv") 
    a.to_html("Table.html") 
    html_file = a.to_html()
    return render_template('dataset.html')

@app.route('/userinput')
def userinput():
    return render_template('userinput.html')


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


@app.route('/graphs')
def graphs():
    #dataset = pd.read_csv("heart.csv")
    #y = dataset["target"]
    #sns.countplot(y)
    #sns.barplot(dataset["sex"],y)
    return render_template('graphs.html')

@app.route('/display')
def display():
    return render_template('display.html')




@app.route('/visuval')
def visuval():
    return render_template('visuval.html')

@app.route('/world_viz')
def world_viz():
    df = pd.read_csv('death.csv')
    fig = go.Figure(data=go.Choropleth(
    locations = df['CODE'],
    z = df['DEATHS (THOUSANDS)'],
    text = df['COUNTRY'],
    colorscale = 'Blues',
    autocolorscale=False,
    reversescale=True,
    marker_line_color='darkgray',
    marker_line_width=0.5,
    colorbar_tickprefix = '',
    colorbar_title = 'DEATHS<br>THOUSANDS',))

    fig.update_layout(
    title_text='WORLD HEART FAILURE DEATHS',
    geo=dict(
        showframe=False,
        showcoastlines=False,
        projection_type='equirectangular'
    ),
    annotations = [dict(
        x=0.5,
        y=0.1,
        xref='paper',
        yref='paper',
        text='Deaths in Thousands',
        showarrow = False
    )]
    )
    
    #fig.show()

    return render_template('visuval.html', world_viz=fig.show())


@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/woh')
def woh():
    return render_template('woh.html')

@app.route('/symptoms')
def symptoms():
    return render_template('symptoms.html')

@app.route('/cause')
def cause():
    return render_template('cause.html')

@app.route('/rfc')
def rfc():
    return render_template('rfc.html')

@app.route('/pre')
def pre():
    return render_template('pre.html')

@app.route('/detect')
def detect():
    return render_template('detect.html')

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

@app.route('/concept')
def concept():
    return render_template('concept.html')

@app.route('/sp')
def sp():
    return render_template('sp.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=True)
