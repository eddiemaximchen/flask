from email_validator import validate_email,EmailNotValidError
from flask import Flask,current_app,g,render_template,request,url_for,redirect,flash,make_response,session
import os
from flask_mail import Mail,Message

app=Flask(__name__)
#for session security
app.config["SECRET_KEY"]="2AZSMss3p5QPbcY2hBsJ"
#mail config
app.config["MAIL_SERVER"]=os.environ.get("MAIL_SERVER")
app.config["MAIL_PORT"]=os.environ.get("MAIL_PORT")
app.config["MAIL_USE_TLS"]=os.environ.get("MAIL_USE_TLS")
app.config["MAIL_USERNAME"]=os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"]=os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"]=os.environ.get("MAIL_DEFAULT_SENDER")

#regist flask mail
mail=Mail(app)
@app.route("/")
def index():
    return "Hello Flaskbook!"

@app.route("/contact")
def contact():
    # retrive Response object
    response = make_response(render_template("contact.html"))
    response.set_cookie("username","Eddie")
    session["username"]="Eddie"
    return response

@app.route("/contact/complete",methods=["GET","POST"])
def contact_complete():
    if request.method=="POST":
        username=request.form["username"]
        email=request.form["email"]
        desc=request.form["desc"]
        is_valid=True
        if not username:
            flash("username required")
            is_valid=False
        if not email:
            flash("email required")
            is_valid=False
        try:
            validate_email(email)
        except EmailNotValidError:
            flash("wrong email format")
            is_valid=False
        
        if not desc:
            flash("commits required")
            is_valid=False

        if not is_valid:
            return redirect(url_for("contact"))
        #send email
            send_email(
                email,
                "Thanks for reaching out",
                username=username,
                desc=desc
            )

        flash("information is sent. Thank you for your contact")
        return redirect(url_for("contact_complete"))
    
    return render_template("contact_complete.html")
def send_email(to,subject,template,**kwargs):
    msg=Message(subject,recipients=[to])
    msg.body=render_template(template+'.txt',**kwargs)
