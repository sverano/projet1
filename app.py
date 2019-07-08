from flask import Flask, request, render_template, redirect, session, abort, url_for, jsonify
import psycopg2
import os
psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)
psycopg2.extensions.register_type(psycopg2.extensions.UNICODEARRAY)
from flask_sqlalchemy import SQLAlchemy
from wtforms.validators import Required
from flask_wtf import FlaskForm, Form
from flask_wtf.form import _Auto
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import timedelta
from wtforms.fields import PasswordField, StringField
from wtforms.validators import Email, EqualTo, InputRequired, ValidationError




app = Flask(__name__)

#app.config.from_object(os.environ['APP_SETTINGS'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://vanick:123456@localhost/base'
app.secret_key = 'gs\xd7\xbd\x17\xc9N\xf3\xae\x1b\xf9\xc5'
app.config['STORMPATH_COOKIE_DURATION'] = timedelta(minutes=30)
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
	password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)])
	remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)])


class ForgotPasswordForm(Form):
    email = StringField('Email', validators=[
        InputRequired('Email address required.'),
        Email('You must provide a valid email address.')
    ])


class ChangePasswordForm(Form):
    password = PasswordField('Password', validators=[InputRequired('Password required.')])
    password_again = PasswordField('Password (again)', validators=[
        InputRequired('Please verify the password.'),
        EqualTo('password', 'Passwords do not match.')
    ])


@app.route('/', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	print(request.method)
	if request.method=="POST":
		user = User.query.filter_by(username=request.form.get('username')).first()
		if user:
			print(user.password)
			if user.password==request.form.get('password'):
				login_user(user, remember=form.remember.data)
				return redirect(url_for('home'))

		return '<h1>Invalid username or password</h1>'

	return render_template('pages/login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm()
	if request.method=="POST":
		print("validated")
		hashed_password = generate_password_hash(form.password.data, method='sha256')
		new_user = User(username=request.form.get('username'), email=request.form.get('email'), password=request.form.get('password'))
		db.session.add(new_user)
		db.session.commit()
		return redirect(url_for('login'))
	return render_template('pages/register.html', form=form)


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
	return render_template('pages/licence/forgot.html')

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
	return render_template('pages/home.html')

@app.route('/licence/algorithmique', methods=['GET', 'POST'])
@login_required
def algorithmique_h():
	global cours
	connec = psycopg2.connect(database="base", user = "vanick", password = "123456", host = "127.0.0.1", port = "5432")
	cux = connec.cursor()
	cux.execute("SELECT * FROM algo")
	cns = cux.fetchall()
	connec.close()
	if request.method == 'POST':
		cours = 'algorithmique'
		return redirect(url_for('emargement_al'))
	return render_template('pages/licence/algorithmique.html', ligne = cns)

@app.route('/licence/robotique', methods=['GET', 'POST'])
@login_required
def robotique_h():
	global cours
	connec = psycopg2.connect(database="base", user = "vanick", password = "123456", host = "127.0.0.1", port = "5432")
	cux = connec.cursor()
	cux.execute("SELECT * FROM robo")
	cns = cux.fetchall()
	connec.close()
	if request.method == 'POST':
		cours = 'robotique'
		return redirect(url_for('emargement_ro'))
	return render_template('pages/licence/robotique.html', ligne = cns)	

@app.route('/licence/programmation', methods=['GET', 'POST'])
@login_required
def programmation_h():
	global cours
	connec = psycopg2.connect(database="base", user = "vanick", password = "123456", host = "127.0.0.1", port = "5432")
	cux = connec.cursor()
	cux.execute("SELECT * FROM prog")
	cns = cux.fetchall()
	connec.close()
	if request.method == 'POST':
		cours = 'programmation'
		return redirect(url_for('emargement_pro'))
	return render_template('pages/licence/programmation.html', ligne = cns)	

@app.route('/licence/algorithmique/emargement', methods=['GET', 'POST'])
@login_required
def emargement_al():
	global cours
	if request.method == 'POST':
		dates = request.form['dates']
		lecon = request.form['lecons']
		absent = request.form['absents']
		connex = psycopg2.connect(database="base", user = "vanick", password = "123456", host = "127.0.0.1", port = "5432")
		cux = connex.cursor()
		if cours == 'algorithmique':
			cux.execute('''CREATE TABLE IF NOT EXISTS algo (dates VARCHAR(15) NOT NULL, lecons VARCHAR(50) NOT NULL, absents VARCHAR(50) NOT NULL)''')
			cux.execute("INSERT INTO algo (dates, lecons, absents) VALUES (%s,%s,%s)", (dates,lecon,absent))
			connex.commit()
			return redirect(url_for('algorithmique_h'))
			connex.close()
	return render_template('pages/licence/emargement.html')


@app.route('/licence/robotique/emargement', methods=['GET', 'POST'])
@login_required
def emargement_ro():
	global cours
	if request.method == 'POST':
		dates = request.form['dates']
		lecon = request.form['lecons']
		absent = request.form['absents']
		connex = psycopg2.connect(database="base", user = "vanick", password = "123456", host = "127.0.0.1", port = "5432")
		cux = connex.cursor()
		if cours == 'robotique':
			cux.execute('''CREATE TABLE IF NOT EXISTS robo (dates VARCHAR(15) NOT NULL, lecons VARCHAR(50) NOT NULL, absents VARCHAR(50) NOT NULL)''')
			cux.execute("INSERT INTO robo (dates, lecons, absents) VALUES (%s,%s,%s)", (dates,lecon,absent))
			connex.commit()
			return redirect(url_for('robotique_h'))
			connex.close()
	return render_template('pages/licence/emargement.html')

@app.route('/licence/programmation/emargement', methods=['GET', 'POST'])
@login_required
def emargement_pro():
	global cours
	if request.method == 'POST':
		dates = request.form['dates']
		lecon = request.form['lecons']
		absent = request.form['absents']
		connex = psycopg2.connect(datavbase="base", user = "vanick", password = "123456", host = "127.0.0.1", port = "5432")
		cux = connex.cursor()
		if cours == 'programmation':
			cux.execute('''CREATE TABLE IF NOT EXISTS prog (dates VARCHAR(15) NOT NULL, lecons VARCHAR(50) NOT NULL, absents VARCHAR(50) NOT NULL)''')
			cux.execute("INSERT INTO prog (dates, lecons, absents) VALUES (%s,%s,%s)", (dates,lecon,absent))
			connex.commit()
			return redirect(url_for('programmation_h'))
			connex.close()
	return render_template('pages/licence/emargement.html')

if __name__ == '__main__':
	app.secret_key = os.urandom(12)
	app.run(debug=True,host='0.0.0.0', port=5000)
	db.init_app(app)
	db.create_all()