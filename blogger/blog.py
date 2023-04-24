import os, sys, pymysql
from flask import Flask,render_template, flash, redirect, url_for, request, current_app, Blueprint, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor,upload_success, upload_fail
from flask_login import LoginManager,UserMixin,login_required, current_user
import logging
from logging.handlers import SMTPHandler, RotatingFileHandler
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_debugtoolbar import DebugToolbarExtension
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditorField
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError
from wtforms import StringField, SubmitField, SelectField, TextAreaField, ValidationError, HiddenField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email, Length, Optional, URL
from datetime import datetime
from threading import Thread
from flask_mail import Message
import click

#目前資料夾的位置
#config
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
# app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret string')
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:Tt-143085@localhost:3306/blogger" #資料庫要自己建
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
ckeditor = CKEditor(app)
mail = Mail(app)
moment = Moment(app)
toolbar = DebugToolbarExtension(app)
migrate = Migrate(app)
bootstrap.init_app(app)
db.init_app(app)
login_manager.init_app(app)
csrf.init_app(app)
ckeditor.init_app(app)
mail.init_app(app)
moment.init_app(app)
toolbar.init_app(app)
migrate.init_app(app, db)

class BaseConfig(object):
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev key')

    DEBUG_TB_INTERCEPT_REDIRECTS = False

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True

    CKEDITOR_ENABLE_CSRF = True
    CKEDITOR_FILE_UPLOADER = 'admin.upload_image'

    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = ('Bluelog Admin', MAIL_USERNAME)

    BLUELOG_EMAIL = os.getenv('BLUELOG_EMAIL')
    BLUELOG_POST_PER_PAGE = 10
    BLUELOG_MANAGE_POST_PER_PAGE = 15
    BLUELOG_COMMENT_PER_PAGE = 15
    # ('theme name', 'display name')
    BLUELOG_THEMES = {'perfect_blue': 'Perfect Blue', 'black_swan': 'Black Swan'}
    BLUELOG_SLOW_QUERY_THRESHOLD = 1

    BLUELOG_UPLOAD_PATH = os.path.join(basedir, 'uploads')
    BLUELOG_ALLOWED_IMAGE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif']

#admin
@login_manager.user_loader
def load_user(user_id):
    user = Admin.query.get(int(user_id))
    return user


login_manager.login_view = 'auth.login'
# login_manager.login_message = 'Your custom message'
login_manager.login_message_category = 'warning'

# url security
try:
    from urllib import urlparse, urljoin
except ImportError:
    from urllib.parse import urlparse, urljoin

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def redirect_back(default='blog.index', **kwargs):
    for target in request.args.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return redirect(target)
    return redirect(url_for(default, **kwargs))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['BLUELOG_ALLOWED_IMAGE_EXTENSIONS']

#data table
class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))
    blog_title = db.Column(db.String(60))
    blog_sub_title = db.Column(db.String(100))
    name = db.Column(db.String(30))
    about = db.Column(db.Text)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True)

    posts = db.relationship('Post', back_populates='category')

    def delete(self):
        default_category = Category.query.get(1)
        posts = self.posts[:]
        for post in posts:
            post.category = default_category
        db.session.delete(self)
        db.session.commit()


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(60))
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    can_comment = db.Column(db.Boolean, default=True)

    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))

    category = db.relationship('Category', back_populates='posts')
    comments = db.relationship('Comment', back_populates='post', cascade='all, delete-orphan')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(30))
    email = db.Column(db.String(254))
    site = db.Column(db.String(255))
    body = db.Column(db.Text)
    from_admin = db.Column(db.Boolean, default=False)
    reviewed = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    replied_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))

    post = db.relationship('Post', back_populates='comments')
    replies = db.relationship('Comment', back_populates='replied', cascade='all, delete-orphan')
    replied = db.relationship('Comment', back_populates='replies', remote_side=[id])
    # Same with:
    # replies = db.relationship('Comment', backref=db.backref('replied', remote_side=[id]),
    # cascade='all,delete-orphan')


class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    url = db.Column(db.String(255))

#view

admin_bp = Blueprint('admin', __name__)
@admin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.blog_title = form.blog_title.data
        current_user.blog_sub_title = form.blog_sub_title.data
        current_user.about = form.about.data
        db.session.commit()
        flash('Setting updated.', 'success')
        return redirect(url_for('blog.index'))
    form.name.data = current_user.name
    form.blog_title.data = current_user.blog_title
    form.blog_sub_title.data = current_user.blog_sub_title
    form.about.data = current_user.about
    return render_template('admin/settings.html', form=form)


@admin_bp.route('/post/manage')
@login_required
def manage_post():
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['BLUELOG_MANAGE_POST_PER_PAGE'])
    posts = pagination.items
    return render_template('admin/manage_post.html', page=page, pagination=pagination, posts=posts)


@admin_bp.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        body = form.body.data
        category = Category.query.get(form.category.data)
        post = Post(title=title, body=body, category=category)
        # same with:
        # category_id = form.category.data
        # post = Post(title=title, body=body, category_id=category_id)
        db.session.add(post)
        db.session.commit()
        flash('Post created.', 'success')
        return redirect(url_for('blog.show_post', post_id=post.id))
    return render_template('admin/new_post.html', form=form)


@admin_bp.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    form = PostForm()
    post = Post.query.get_or_404(post_id)
    if form.validate_on_submit():
        post.title = form.title.data
        post.body = form.body.data
        post.category = Category.query.get(form.category.data)
        db.session.commit()
        flash('Post updated.', 'success')
        return redirect(url_for('blog.show_post', post_id=post.id))
    form.title.data = post.title
    form.body.data = post.body
    form.category.data = post.category_id
    return render_template('admin/edit_post.html', form=form)


@admin_bp.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted.', 'success')
    return redirect_back()


@admin_bp.route('/post/<int:post_id>/set-comment', methods=['POST'])
@login_required
def set_comment(post_id):
    post = Post.query.get_or_404(post_id)
    if post.can_comment:
        post.can_comment = False
        flash('Comment disabled.', 'success')
    else:
        post.can_comment = True
        flash('Comment enabled.', 'success')
    db.session.commit()
    return redirect_back()


@admin_bp.route('/comment/manage')
@login_required
def manage_comment():
    filter_rule = request.args.get('filter', 'all')  # 'all', 'unreviewed', 'admin'
    page = request.args.get('page', 1, type=int)
    per_page = current_app.config['BLUELOG_COMMENT_PER_PAGE']
    if filter_rule == 'unread':
        filtered_comments = Comment.query.filter_by(reviewed=False)
    elif filter_rule == 'admin':
        filtered_comments = Comment.query.filter_by(from_admin=True)
    else:
        filtered_comments = Comment.query

    pagination = filtered_comments.order_by(Comment.timestamp.desc()).paginate(page, per_page=per_page)
    comments = pagination.items
    return render_template('admin/manage_comment.html', comments=comments, pagination=pagination)


@admin_bp.route('/comment/<int:comment_id>/approve', methods=['POST'])
@login_required
def approve_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    comment.reviewed = True
    db.session.commit()
    flash('Comment published.', 'success')
    return redirect_back()


@admin_bp.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted.', 'success')
    return redirect_back()


@admin_bp.route('/category/manage')
@login_required
def manage_category():
    return render_template('admin/manage_category.html')


@admin_bp.route('/category/new', methods=['GET', 'POST'])
@login_required
def new_category():
    form = CategoryForm()
    if form.validate_on_submit():
        name = form.name.data
        category = Category(name=name)
        db.session.add(category)
        db.session.commit()
        flash('Category created.', 'success')
        return redirect(url_for('.manage_category'))
    return render_template('admin/new_category.html', form=form)


@admin_bp.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    form = CategoryForm()
    category = Category.query.get_or_404(category_id)
    if category.id == 1:
        flash('You can not edit the default category.', 'warning')
        return redirect(url_for('blog.index'))
    if form.validate_on_submit():
        category.name = form.name.data
        db.session.commit()
        flash('Category updated.', 'success')
        return redirect(url_for('.manage_category'))

    form.name.data = category.name
    return render_template('admin/edit_category.html', form=form)


@admin_bp.route('/category/<int:category_id>/delete', methods=['POST'])
@login_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if category.id == 1:
        flash('You can not delete the default category.', 'warning')
        return redirect(url_for('blog.index'))
    category.delete()
    flash('Category deleted.', 'success')
    return redirect(url_for('.manage_category'))


@admin_bp.route('/link/manage')
@login_required
def manage_link():
    return render_template('admin/manage_link.html')


@admin_bp.route('/link/new', methods=['GET', 'POST'])
@login_required
def new_link():
    form = LinkForm()
    if form.validate_on_submit():
        name = form.name.data
        url = form.url.data
        link = Link(name=name, url=url)
        db.session.add(link)
        db.session.commit()
        flash('Link created.', 'success')
        return redirect(url_for('.manage_link'))
    return render_template('admin/new_link.html', form=form)


@admin_bp.route('/link/<int:link_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_link(link_id):
    form = LinkForm()
    link = Link.query.get_or_404(link_id)
    if form.validate_on_submit():
        link.name = form.name.data
        link.url = form.url.data
        db.session.commit()
        flash('Link updated.', 'success')
        return redirect(url_for('.manage_link'))
    form.name.data = link.name
    form.url.data = link.url
    return render_template('admin/edit_link.html', form=form)


@admin_bp.route('/link/<int:link_id>/delete', methods=['POST'])
@login_required
def delete_link(link_id):
    link = Link.query.get_or_404(link_id)
    db.session.delete(link)
    db.session.commit()
    flash('Link deleted.', 'success')
    return redirect(url_for('.manage_link'))


@admin_bp.route('/uploads/<path:filename>')
def get_image(filename):
    return send_from_directory(current_app.config['BLUELOG_UPLOAD_PATH'], filename)


@admin_bp.route('/upload', methods=['POST'])
def upload_image():
    f = request.files.get('upload')
    if not allowed_file(f.filename):
        return upload_fail('Image only!')
    f.save(os.path.join(current_app.config['BLUELOG_UPLOAD_PATH'], f.filename))
    url = url_for('.get_image', filename=f.filename)
    return upload_success(url, f.filename)

#forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(1, 128)])
    remember = BooleanField('Remember me')
    submit = SubmitField('Log in')


class SettingForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(1, 30)])
    blog_title = StringField('Blog Title', validators=[DataRequired(), Length(1, 60)])
    blog_sub_title = StringField('Blog Sub Title', validators=[DataRequired(), Length(1, 100)])
    about = CKEditorField('About Page', validators=[DataRequired()])
    submit = SubmitField()


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(1, 60)])
    category = SelectField('Category', coerce=int, default=1)
    body = CKEditorField('Body', validators=[DataRequired()])
    submit = SubmitField()

    def __init__(self, *args, **kwargs):
        super(PostForm, self).__init__(*args, **kwargs)
        self.category.choices = [(category.id, category.name)
                                 for category in Category.query.order_by(Category.name).all()]


class CategoryForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(1, 30)])
    submit = SubmitField()

    def validate_name(self, field):
        if Category.query.filter_by(name=field.data).first():
            raise ValidationError('Name already in use.')


class CommentForm(FlaskForm):
    author = StringField('Name', validators=[DataRequired(), Length(1, 30)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(1, 254)])
    site = StringField('Site', validators=[Optional(), URL(), Length(0, 255)])
    body = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField()


class AdminCommentForm(CommentForm):
    author = HiddenField()
    email = HiddenField()
    site = HiddenField()


class LinkForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(1, 30)])
    url = StringField('URL', validators=[DataRequired(), URL(), Length(1, 255)])
    submit = SubmitField()

#email

def _send_async_mail(app, message):
    with app.app_context():
        mail.send(message)


def send_mail(subject, to, html):
    app = current_app._get_current_object()
    message = Message(subject, recipients=[to], html=html)
    thr = Thread(target=_send_async_mail, args=[app, message])
    thr.start()
    return thr


def send_new_comment_email(post):
    post_url = url_for('blog.show_post', post_id=post.id, _external=True) + '#comments'
    send_mail(subject='New comment', to=current_app.config['BLUELOG_EMAIL'],
              html='<p>New comment in post <i>%s</i>, click the link below to check:</p>'
                   '<p><a href="%s">%s</a></P>'
                   '<p><small style="color: #868e96">Do not reply this email.</small></p>'
                   % (post.title, post_url, post_url))


def send_new_reply_email(comment):
    post_url = url_for('blog.show_post', post_id=comment.post_id, _external=True) + '#comments'
    send_mail(subject='New reply', to=comment.email,
              html='<p>New reply for the comment you left in post <i>%s</i>, click the link below to check: </p>'
                   '<p><a href="%s">%s</a></p>'
                   '<p><small style="color: #868e96">Do not reply this email.</small></p>'
                   % (comment.post.title, post_url, post_url))

class RequestFormatter(logging.Formatter):
    def format(self, record):
        record.url = request.url
        record.remote_addr = request.remote_addr
        return super(RequestFormatter, self).format(record)
request_formatter = RequestFormatter(
    '[%(asctime)s] %(remote_addr)s requested %(url)s\n'
    '%(levelname)s in %(module)s: %(message)s'
)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler = RotatingFileHandler(os.path.join(basedir, 'logs/bluelog.log'),
                                   maxBytes=10 * 1024 * 1024, backupCount=10)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
mail_handler = SMTPHandler(
    mailhost=app.config['MAIL_SERVER'],
    fromaddr=app.config['MAIL_USERNAME'],
    toaddrs=['ADMIN_EMAIL'],
    subject='Bluelog Application Error',
    credentials=(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD']))
mail_handler.setLevel(logging.ERROR)
mail_handler.setFormatter(request_formatter)
if not app.debug:
    app.logger.addHandler(mail_handler)
    app.logger.addHandler(file_handler)

def register_shell_context(app):
    @app.shell_context_processor
    def make_shell_context():
        return dict(db=db, Admin=Admin, Post=Post, Category=Category, Comment=Comment)
    
def register_template_context(app):
    @app.context_processor
    def make_template_context():
        admin = Admin.query.first()
        categories = Category.query.order_by(Category.name).all()
        links = Link.query.order_by(Link.name).all()
        if current_user.is_authenticated:
            unread_comments = Comment.query.filter_by(reviewed=False).count()
        else:
            unread_comments = None
        return dict(
            admin=admin, categories=categories,
            links=links, unread_comments=unread_comments)
    
@app.errorhandler(400)
def bad_request(e):
     return render_template('errors/400.html'), 400
@app.errorhandler(404)
def page_not_found(e):
     return render_template('errors/404.html'), 404
@app.errorhandler(500)
def internal_server_error(e):
     return render_template('errors/500.html'), 500
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
     return render_template('errors/400.html', description=e.description), 400

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
@click.option('--username', prompt=True, help='The username used to login.')
@click.option('--password', prompt=True, hide_input=True,
               confirmation_prompt=True, help='The password used to login.')
def init(username, password):
     """Building Bluelog, just for you."""
     click.echo('Initializing the database...')
     db.create_all()
     admin = Admin.query.first()
     if admin is not None:
         click.echo('The administrator already exists, updating...')
         admin.username = username
         admin.set_password(password)
     else:
         click.echo('Creating the temporary administrator account...')
         admin = Admin(
             username=username,
             blog_title='Bluelog',
             blog_sub_title="No, I'm the real thing.",
             name='Admin',
             about='Anything about you.'
         )
         admin.set_password(password)
         db.session.add(admin)
     category = Category.query.first()
     if category is None:
         click.echo('Creating the default category...')
         category = Category(name='Default')
         db.session.add(category)
     db.session.commit()
     click.echo('Done.')
