from flask import Flask
from view.api import app2

app=Flask(__name__)

@app.route("/")
def index():
    return "hello index"

app.register_blueprint(app2) 
