from forms import LoginForm
from flask import Flask,render_template
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secret string')

@app.route('/basic',methods=['GET','POST'])
def basic():
    form=LoginForm()
    return render_template('basic.html',form=form)

if __name__ == '__main__':

    app.run(debug=True)
