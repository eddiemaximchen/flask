from flask import Flask,flash, redirect, url_for, render_template
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
import pymysql,os,click
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length

#目前資料夾的位置
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret string')
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:root@localhost:3306/messagebook" #資料庫要自己建
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db = SQLAlchemy(app)

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

bootstrap = Bootstrap(app)
moment = Moment(app)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    body = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

@app.shell_context_processor  #讓crud的form=form集中在這做
def make_shell_context():   
    return dict(db=db,Message=Message) #資料庫＝資料庫 資料表＝資料表

@app.cli.command()
def initdb():
    db.create_all()                     #看到 SQL 語法表示資料表建立成功
    click.echo('Initialized database.')

class HelloForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(1, 20)])
    body = TextAreaField('Message', validators=[DataRequired(), Length(1, 200)])
    submit = SubmitField()

@app.cli.command()
@click.option('--drop', is_flag=True, help='Create after drop.')
def initdb(drop):
    """Initialize the database."""
    if drop:
        click.confirm('This operation will delete the database, do you want to continue?', abort=True)
        db.drop_all()
        click.echo('Drop tables.')
    db.create_all()
    click.echo('Initialized database.')


@app.cli.command()
@click.option('--count', default=20, help='Quantity of messages, default is 20.')
def forge(count):
    """Generate fake messages."""
    from faker import Faker

    db.drop_all()
    db.create_all()

    fake = Faker()
    click.echo('Working...')

    for i in range(count):
        message = Message(
            name=fake.name(),
            body=fake.sentence(),
            timestamp=fake.date_time_this_year()
        )
        db.session.add(message)

    db.session.commit()
    click.echo('Created %d fake messages.' % count)

@app.route('/', methods=['GET', 'POST'])
def index():
    form = HelloForm()
    if form.validate_on_submit():
        name = form.name.data
        body = form.body.data
        message = Message(body=body, name=name)
        db.session.add(message)
        db.session.commit()
        flash('Your message have been published!')
        return redirect(url_for('index'))

    messages = Message.query.order_by(Message.timestamp.desc()).all()
    return render_template('index.html', form=form, messages=messages)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

