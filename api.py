from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///movies.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))
    email = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    bio = db.Column(db.String(50))
    must_watch = db.Column(db.String(50))
    public_id = db.Column(db.String(50), unique = True)

def token_required(f):
    """
    Checks if the token passed in the header is valid 
    (required for endpoints that will require user to be authenticated)
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None #intializes an empty token
        if 'x-access-token' in request.headers:  #checks if a token is passed 
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message':'Token is missing'}), 401 #returns a message if token is not passed
        
        try:  #if the token is there then we move on to here to check if the token is valid and not expired 
            data = jwt.decode(token, app.config['SECRET_KEY'])  #takes in token as data and verifies with secret key
            current_user = User.query.filter_by(public_id = data['public_id']).first() #query the db to the user that token belongs to
        except: 
            return jsonify({'message':'Invalid Token'}), 401
        return f(current_user, *args,**kwargs) #pass that user object to the route 

        #To use this for any enpoint that requires verification simply use:
        #@token_required and add current_user to your fn parameters 

    return decorated




@app.route('/user', methods =['POST'])
def register_user():
    """
    Simply registers a user with a username and password.
    """
    data = request.get_json() #gets the json response
    hashed_password = generate_password_hash(data['password'], method = 'sha256') #hashes passwords using sha256
    new_user = User(public_id=str(uuid.uuid4()), username = data['username'], password = hashed_password, admin = True)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message':'New User has been created successfully'})


@app.route('/login')
def login():
    """
    Generates token and logs the user in then returns token :) no black magic here, move on....
    """
    auth = request.authorization 

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify this user', 401, {'WWW-example-auth-URL':'Basic realm = "login required"'})

    user = User.query.filter_by(username = auth.username).first()

    if not user:
        return jsonify({'message': ' no user found'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'expiration':str(datetime.datetime.utcnow() + datetime.timedelta(minutes=60))}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8'),
        'message':'Token successfully generated, expiration time 60 minutes :) '
        })
    
    return make_response('could not verify this user', 401, {'WWW-example-auth-URL':'Basic realm = "login required"'})




@app.route('/user/info/<public_id>', methods = ['PUT'])
@token_required
def update_user_info(current_user, public_id):
    """
    This endpoint enables the user to update his info after registering/logging in. 
    Info such as bio, must_watch, email... 
    """
    data = request.get_json()
    user = User.query.filter_by(public_id = public_id).first()
    user.email = data['email']
    user.bio = data['bio']
    user.must_watch = data['must_watch']
    print(data)
    db.session.commit()
    return jsonify({'message': 'User Information has been updated successfully'}), 201


@app.route('/user', methods = ['GET'])
@token_required
def get_all_users(current_user): #ADMIN ONLY
    """
    gets all users data, ADMIN ONLY
    Just so we can see the userbase we are working with here 
    """
    if not current_user.admin:
        return jsonify({'message':'insufficient Admin privelleges'})
    
    users = User.query.all()
    output = [] 
    for user in users:
        user_data = {}
        user_data['public_id']=user.public_id
        user_data['username']=user.username
        user_data['email']= user.email
        user_data['password']=user.password
        user_data['admin']=user.admin
        user_data['must_watch']=user.must_watch
        user_data['bio']=user.bio
        output.append(user_data)
    return jsonify({'users':output})



if __name__ == '__main__':
    app.run(debug = True)