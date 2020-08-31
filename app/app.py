from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from tmdbv3api import TMDb, Movie



app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///movies.db'

db = SQLAlchemy(app)
tmdb = TMDb()
tmdb.api_key = '31983801561a84bd8ebd7fe2ac3e4685'

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))
    email = db.Column(db.String(80),nullable=True)
    admin = db.Column(db.Boolean)
    bio = db.Column(db.String(50),nullable=True)
    must_watch = db.Column(db.String(50), nullable=True)
    public_id = db.Column(db.String(50), unique = True)
    user_movie_id = db.Column(db.Integer, nullable=True)
    user_title = db.Column(db.String(150),nullable=True)
    user_overview = db.Column(db.String(1000),nullable=True)
    user_rate = db.Column(db.String(50),nullable=True)


class Movie_db(db.Model):
    movie_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    overview = db.Column(db.String(1000))
    rate = db.Column(db.String(50))

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


@app.route('/user', methods =['POST'])
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

#Movie endpoints

@app.route('/movie', methods=['POST'])
@token_required
def add_movies(current_user):
    """
    This endpoint "feeds" data directly to my database from TMDb API 
    to automate the process we go through a range of movie IDs (eg:from 1 to 500) and save their data respectively 
    The user has two options to add movies either from my database or from directly searching TMBd API for all movies there 
    """
    movie = Movie()
    movieid=300  #sets a starting point to the range of movie IDs i will be adding from
    movies = []
    #popular = movie.popular()
    while movieid <= 320:  #movieIDs ending points
        movieid = movieid + 1   #increments counter
        popular = movie.details(movieid) #grabs movie details from TMDb
        #if not popular.title:
        #    movieid = movieid + 1 #sometimes no movie exists for the given ID on TMDb's database
        #else:
        popular = movie.details(movieid)
        #print(movieid)
        new_movie = Movie_db(movie_id = movieid, title= popular.title, overview = popular.overview, rate = popular.vote_average)
        movies.append({'id': movieid,'title':popular.title, 'overview':popular.overview, 'rate':popular.vote_average}) 
        db.session.add(new_movie)  # Saves my movies list to the database
        db.session.commit()  
    return jsonify({'movies':movies})    

@app.route('/movie',methods = ['GET'])
def display_movies():
    """
    Displays all the data entered by the above endpoint
    """
    movie_list = Movie_db.query.all()
    movies = []
    for movie in movie_list:
        movies.append({'id': movie.movie_id, 'title': movie.title, 'overview':movie.overview, 'rate':movie.rate})

    return jsonify({'movies':movies})

@app.route('/user/<public_id>/movies', methods = ['POST'])
def add_user_movies(public_id):
    """
    User has the option to search our own database using movie title, the movie is automatically added to their list
    User also has the option to pass a "rating" for the movie in this endpoint for the given movie
    """
    data = request.get_json()
    user_movie = Movie_db.query.filter_by(title = data['title']).first()
    print(user_movie.movie_id)
    print(user_movie.title)
    print(user_movie.overview)
    print(user_movie.rate)
    user = User.query.filter_by(public_id = public_id).first()
    user.user_movie_id = user_movie.movie_id 
    user.user_overview = user_movie.overview
    user.user_rate = data['rating']
    user.user_title = user_movie.title
    db.session.commit()
    return jsonify({'message': 'User Information has been updated successfully'}), 201

@app.route('/user/<public_id>/movies', methods = ['PUT'])
def edit_movie_rating(public_id):
    """
    Allows the user to edit his own rating for a movie
    """
    data = request.get_json()
    user = User.query.filter_by(public_id = public_id).first()
    user.user_rate = data['rating']
    db.session.commit()

    







if __name__ == '__main__':
    app.run(debug = True)