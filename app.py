from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from tmdbv3api import TMDb, Movie
import ssl
import urllib.request as req
import json
import requests


app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///movies.db'

db = SQLAlchemy(app)
tmdb = TMDb()
tmdb.api_key = '31983801561a84bd8ebd7fe2ac3e4685'
base_url = "https://api.themoviedb.org/3/discover/movie/?api_key="+tmdb.api_key

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))
    email = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    bio = db.Column(db.String(50),nullable=True)
    must_watch = db.Column(db.String(50), nullable=True)
    public_id = db.Column(db.String(50), unique = True)

class Movie(db.Model): #this is the movie model which acts as the user's personal list of movies and their data
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50))
    overview = db.Column(db.String(1000))
    poster = db.Column(db.String(50))
    vote_average = db.Column(db.String(20))
    vote_count = db.Column(db.String(20))
    user_rating = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey('user.public_id'))


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


#user endpoints 


@app.route('/register', methods =['POST'])
def register_user():
    """
    Simply registers a user with a username and password.
    """
    data = request.get_json() 
    hashed_password = generate_password_hash(data['password'], method = 'sha256') #hashes passwords using sha256
    new_user = User(public_id=str(uuid.uuid4()), username = data['username'], password = hashed_password, admin = True)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message':'New User has been created successfully'})


@app.route('/login')
def login():
    """
    Generates token and logs the user in then returns token 
    """
    auth = request.authorization 

    if not auth or not auth.username or not auth.password: #if there is no authenticated user/pass throws an error
        return make_response('could not verify this user', 401, {'WWW-example-auth-URL':'Basic realm = "login required"'})

    user = User.query.filter_by(username = auth.username).first()

    if not user: #if user doesn't exist
        return jsonify({'message': ' no user found'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'expiration':str(datetime.datetime.utcnow() + datetime.timedelta(minutes=60))}, app.config['SECRET_KEY'])
        #if user credientals are valid generates token for 60 mins
        return jsonify({'token': token.decode('UTF-8'),
        'message':'Token successfully generated, expiration time 60 minutes :) '
        })
    
    return make_response('could not verify this user', 401, {'WWW-example-auth-URL':'Basic realm = "login required"'})


@app.route('/user/info', methods = ['PUT'])
@token_required
def update_user_info(current_user):
    """
    This endpoint enables the user to update his info after registering/logging in. 
    Info such as bio, must_watch, email... 
    """
    data = request.get_json()
    user = User.query.filter_by(public_id =current_user.public_id).first() #filters user data by public id
    user.email = data['email'] #update email, bio must watch
    user.bio = data['bio']
    user.must_watch = data['must_watch']
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

#Movie endpoints

@app.route('/discover', methods = ['GET'])
def tmdb_movies():
    """
    Displays over 10k movie results from tmdb
    (Authentication not required)
    """
    ssl._create_default_https_context = ssl._create_unverified_context
    connection = req.urlopen(base_url) 
    data = json.loads(connection.read())
    movie_results_list = data['results']
    return jsonify({'Discover Movies': movie_results_list})


@app.route('/search', methods = ['GET'])
def search_movie():
    """
    Search for the name of a movie from TMDb database
   (Authentication not required)
    """
    data = request.get_json()
    movie_name = data['title']
    search_movie_url = 'https://api.themoviedb.org/3/search/movie?api_key={}&query={}'.format(tmdb.api_key, movie_name)
    search_movie_response = requests.get(search_movie_url).json()
    return jsonify({'message':search_movie_response['results']})

@app.route('/add', methods = ['POST'])
@token_required
def add_movie(current_user):
    """
    add movie to database (user list) by the movie's id and add your own user rate to it 
    Requires Authentication
    """
    data = request.get_json()
    movie_id = data['id']
    id_url = 'https://api.themoviedb.org/3/movie/{}?api_key={}'.format(movie_id, tmdb.api_key)
    movie_id_response = requests.get(id_url).json()
    movie_info = Movie(id = movie_id , title = movie_id_response['original_title'], overview = movie_id_response['overview'], user_rating = data['rate'],user_id = current_user.public_id, )
    db.session.add(movie_info)
    db.session.commit()  
    #moviename = movie_id_response['original_title']
    #print(movie_id_response['original_title'])
    #print(movie_id_response['overview'])
    #print(current_user.public_id)
    return jsonify({'msg':'The movie ' +movie_id_response['original_title']+ ' has been added to your list'})


@app.route('/edit', methods = ['PUT'])
@token_required
def edit_user_rating(current_user):
    """
    updates the user rating, takes in ID of the movie and the rate you want to update
    Requires Authentication
    """
    data = request.get_json()
    query = Movie.query.filter_by(id = data['id']).first() 
    query.user_rating = data['rate']
    db.session.commit()
    return jsonify({'message': 'rating for movie ' + query.title +' has been updated with '+query.user_rating+' '})


@app.route('/delete-movie', methods = ['DELETE'])
@token_required
def delete_movie(current_user):
    """
    Deletes Movie from the user list
    Requires Authentication
    """
    data = request.get_json()
    query = Movie.query.filter_by(id = data['id']).first()
    db.session.delete(query)
    db.session.commit()
    return jsonify ({'message': 'The movie '+query.title+' has been deleted'})


@app.route('/add', methods = ['GET'])
@token_required
def user_movie_list(current_user):
    """
    Displays all movies in a User's movie List
    Requires Authentication
    """ 
    query = Movie.query.all()
    movies = []
    for q in query:
        movies.append({'id': q.id, 'title':q.title, 'overview':q.overview, 'user':q.user_id, 'user rating':q.user_rating})

    return jsonify ({'data': movies})


if __name__ == '__main__':
    app.run(debug = True)