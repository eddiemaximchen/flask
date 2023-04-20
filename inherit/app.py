from flask import Flask,render_template,url_for,Markup,flash,redirect


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
    return render_template('index.html')

@app.template_filter()
def musical(s):
    return s + Markup('&#9835;')

@app.template_global()
def bar():
    return 'I am bar'
@app.context_processor
def inject_foo():
    foo='I am foo.'
    return dict(foo=foo)

@app.route('/watchlist')
def watchlist():
    return render_template('watchlist.html',user=user,movies=movies)

@app.template_test()
def baz(n):
    if n == 'baz':
        return True
    return False

# @app.route('/watchlist2')
# def watchlist_with_static():
    # return render_template('watchlist_with_static.html', user=user, movies=movies)
# 
# 
# message flashing
# @app.route('/flash')
# def just_flash():
    # flash('I am flash, who is looking for me?')
    # return redirect(url_for('index'))
# 
# 
# 404 error handler
# @app.errorhandler(404)
# def page_not_found(e):
    # return render_template('errors/404.html'), 404
# 
# 
# 500 error handler
# @app.errorhandler(500)
# def internal_server_error(e):
    # return render_template('errors/500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)




