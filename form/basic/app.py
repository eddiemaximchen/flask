from forms import LoginForm
from flask import Flask,render_template,request
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secret string')
username={
        'username':'eddie'
}

@app.route('/basic',methods=['GET','POST'])
def basic():
    form=LoginForm()
    if request.method=="POST" and form.validate():
        username = form.username.data
        return 'ok'
    return render_template('basic.html',form=form,username=username)


if __name__ == '__main__':

    app.run(debug=True)
