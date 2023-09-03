from flask import Flask, jsonify, request, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message, Mail
from secretKey import strongKey
from datetime import datetime, timedelta
from pathlib import Path
import os




app = Flask(__name__)
app.config['MAIL_SERVER'] = ''
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['USE_TLS'] = True
app.config['USE_SSL'] = False
# instancePath = os.path.abspath('instance')
# dbURI = f'sqlite:///{os.path.join(instancePath, "app.db")}'
app.config['SECRET_KEY'] = 'INSERT_SECRET_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
app.config['JWT_SECRET_KEY'] = strongKey
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)


class User(db.Model):
	userId = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True, nullable=False)
	email = db.Column(db.String(120), unique=True, nullable=False)
	passwordHash = db.Column(db.String(120), nullable=False)
	resetPassToken = db.Column(db.String(120), nullable=False)
	resetPassEx = db.Column(db.DateTime)

@app.route('/',methods=['GET'])
def index():
	return jsonify(message='Welcome To JLoAuth'),200


@app.route('/register', methods=['POST'])
def register():

	info = request.get_json()

	#extract user info from request
	username = info.get('username')	
	email = info.get('email')
	password = info.get('password')

	#check for duplicate username and email
	if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
		return jsonify(message='Username or Email Is Already Registered'),400

	#password hashing
	hashedPassword = bcrypt.generate_password_hash(password.encode('utf-8'))

	#creation of new user 
	newUser = User(username=username, email=email, passwordHash = hashedPassword )
	db.session.add(newUser)
	db.session.commit()

	#generate access token
	accessToken = create_access_token(identity=username)

	return jsonify(message='User Registered Successfully ✅',accessToken = accessToken),201

@app.route('/login',methods =['POST'])
def login():
	info = request.get_json()

	#extract user login info
	username = info.get('username')
	password = info.get('password')

	#find user through username query search
	user = User.query.filter_by(username=username).first()

	#check if user exists and password matches
	if not user or not bcrypt.check_password_hash(user.passwordHash,password):
		return jsonify(message='Invalid Credentials ❌'),401

	#generate access token
	accessToken = create_access_token(identity,user.username)

	return jsonify(message='Logged In Successfully ✅',accessToken = accessToken)

@app.route('/request-password-reset',methods=['GET','POST'])
def reset_password_request():
	email = request.get_json().get('email')
	user = User.query.filter_by(email=email).first()

	if user:
		token = reset_token_gen(user)
		send_pass_reset_email(emaill,token)
		return jsonify(message='Instructions to reset your password have been sent to your email'),200
	else:
		return jsonify(message='Email not found'),404
	

@app.route('/reset-password/<token>',methods=['POST'])
def reset_password(token):
	try:
		email = serializer.loads(token,salt='password-reset',max_age=3600)
		user = User.query.filter_by(email=email).first()
		if user:
			new_password = request.get_json().get('new_password')
			user.passwordHash = bcrypt.generate_password_hash(new_password.encode('utf-8'))
			db.session.commit()
			return jsonify(message='Password reset successful. Log in with your new password.'),200
		else:
			return jsonify(message ='Invalid or expired password reset link'),400
	except Exception as e:
		return jsonify(message='Invalid or expired password reset link'),400


def reset_token_gen(user):
	token = serailizer.dumps(user.email,sale='password-reset')
	user.resetPassToken = token
	user.resetPassEx = datetime.utcnow() + timedelta(hours=1)
	db.session.commit()
	return token


def send_pass_reset_email(email,token):
	msg = Message('Password Reset',sender='',recipients=[email])
	reset_link = f'http://url/reset_password/{token}'
	msg.body = f'Click on the link to reset your password: {reset_link}'
	mail.send(msg)


#Protected endpoint
@app.route('/protected',methods=['GET'])
@jwt_required()
def protected():
	#access users identity
	currentUser = get_jwt_identity()
	return jsonify(logged_in_as=currentUser),200

if __name__ == '__main__':
	with app.app_context():
		db.create_all()
	app.run(debug=True)

