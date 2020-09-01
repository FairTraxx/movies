# Flask Movies API
Documentation: https://documenter.getpostman.com/view/11720989/TVCe294L#ed30dfe6-6d6d-4508-91f5-3a6b1f4b34c9

Also the api is deployed here: https://flask-movie-tmbd.herokuapp.com/

## Features: 

1. Register and Login

1. Display all users and their data (admin=True only)

1. Add or update personal user info (e.g bio, email, must watch movies)

1. Get a list of all movies in TMDb's database 

1. Search a specefic movie by name

1. Add a movie to your list and rate it

1. Edit that rating

1. Delete the movie and it's data from your list

### Setup 

1. Install flask and virtual env `pip install flask` `pip install venv` 

1. Create a virtual environment `python -m venv <env_name>`

   * Activate your virtual environment
  
   Windows/Powershell `<venv_name>\Scripts\activate`
   
   linux/macosx `source <venv_name>/bin/activate`

1. Set flask app path using `export FLASK_APP=app.py` 

1. Set flask env path using `export FLASK_ENV=<env_name>`

1. then type `flask run`

1. profit ?
