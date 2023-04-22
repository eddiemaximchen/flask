'''
mysql version
'''
import os
import pymysql
from flask_sqlalchemy import SQLAlchemy
import click
from flask import Flask
from flask import redirect, url_for, abort, render_template, flash
from flask_wtf import FlaskForm
from wtforms import SubmitField, TextAreaField
from wtforms.validators import DataRequired

#目前資料夾的位置
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret string')
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:root@localhost:3306/guestbook" #資料庫要自己建
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db = SQLAlchemy(app)

# Models
class Contacts(db.Model):                   #資料表格式 資料表名稱 首字彙變小寫 可用__tablename__來自訂資料表名稱
    name=db.Column(db.VARCHAR(20),primary_key=True)
    phone_number=db.Column(db.VARCHAR(50))
    

@app.cli.command()
def initdb():
    db.create_all()                     #看到 SQL 語法表示資料表建立成功
    click.echo('Initialized database.')

#Forms
class NewContactForm(FlaskForm):
    name=TextAreaField('Name',validators=[DataRequired()])
    phone_number=TextAreaField('Phone_number',validators=[DataRequired()])
    submit=SubmitField('Save')

class EditContactForm(FlaskForm):
    phone_number=TextAreaField('Phone_number',validators=[DataRequired()])
    submit=SubmitField('Update')

class DeleteContactForm(FlaskForm):
    submit=SubmitField('Delete')

@app.route("/")
def index():
    form=DeleteContactForm()
    contacts=Contacts.query.all()
    return render_template('index.html',contacts=contacts,form=form)

@app.route("/new",methods=['GET','POST'])
def new_contact():
    form=NewContactForm()
    if form.validate_on_submit():
        name=form.name.data
        phone_number=form.phone_number.data
        contact=Contacts(name=name,phone_number=phone_number)
        db.session.add(contact)
        db.session.commit()
        flash('This contact is saved')
        return redirect(url_for('index'))
    return render_template('new_contact.html',form=form)

@app.route("/edit/<name>",methods=['GET','POST'])
def edit_contact(name):
    form=EditContactForm()
    contact=Contacts.query.get(name)
    if form.validate_on_submit():
        contact.phone_number=form.phone_number.data
        db.session.commit()
        flash('This contact is updated')
        return redirect(url_for('index'))
    form.phone_number.data=contact.phone_number
    return render_template('edit_contact.html',form=form)

@app.route("/delete/<name>",methods=['GET','POST'])
def delete_contact(name):
    form=DeleteContactForm()
    if form.validate_on_submit():
        contact=Contacts.query.get(name)
        db.session.delete(contact)
        db.session.commit()
        flash('This contact is deleted')
    else:
        abort(400)
    return redirect(url_for('index'))

