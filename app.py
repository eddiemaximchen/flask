from flask import Flask,render_template,url_for


app = Flask(__name__)

user={
    'username':'Grey li',
    'bio':'A boy who loves movies and music.'
}
movies=[
    {'name':'my neighbor','year':'1998'},
    {'name':'Forrest Gump','year':"1993"},
]

@app.route('/')
def index():
    return render_template('index.html',user=user,movies=movies)
if __name__ == '__main__':

    app.run(debug=True)




 
