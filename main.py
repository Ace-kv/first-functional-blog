import os
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship, Mapped
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, RequestResetForm, ResetPasswordForm
from forms import CreatePostForm
from secrets import token_hex
import bleach
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail, Message
from dotenv import load_dotenv

load_dotenv()


'''
Make sure the required packages are installed: 
Open the Terminal 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = token_hex(32)
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

# Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
if os.environ.get("LOCAL") == "True":
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///posts.db"
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI")
# app.config['SQLALCHEMY_BINDS'] = {'users': 'sqlite:///blog.db'} ## for connecting a separate database(s)
db = SQLAlchemy()
db.init_app(app)

# MAIL CONFIG
app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("My_Email_g")
app.config['MAIL_PASSWORD'] = os.getenv("My_Password_g")

mail = Mail(app)

salt = ""


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    author_id: Mapped[int] = db.Column(db.ForeignKey("blog_users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author: Mapped["User"] = relationship(back_populates="posts")
    img_url = db.Column(db.String(250), nullable=False)
    comments: Mapped[list["Comment"]] = relationship(back_populates="parent_post")


class User(UserMixin, db.Model):
    # __bind_key__ = "users"
    __tablename__ = "blog_users"
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts: Mapped[list["BlogPost"]] = relationship(back_populates="author")
    comments: Mapped[list["Comment"]] = relationship(back_populates="comment_author")

    def get_reset_token(self):
        global salt
        salt = token_hex(16)
        s = Serializer(app.config['SECRET_KEY'], salt=salt)
        return s.dumps(self.id)

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        global salt
        s = Serializer(app.config['SECRET_KEY'], salt=salt)
        try:
            user_id = s.loads(token, max_age=expires_sec)
        except:
            return None
        return db.get_or_404(User, user_id)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id: Mapped[int] = db.Column(db.ForeignKey("blog_users.id"))
    comment_author: Mapped["User"] = relationship(back_populates="comments")
    post_id: Mapped[int] = db.Column(db.ForeignKey("blog_posts.id"))
    parent_post: Mapped["BlogPost"] = relationship(back_populates="comments")
    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


# strips invalid tags/attributes
def strip_invalid_html(content):
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt',
                    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
                    'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike',
                    'span', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
                    'thead', 'tr', 'tt', 'u', 'ul']

    allowed_attrs = {
        'a': ['href', 'target', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }

    cleaned = bleach.clean(content,
                           tags=allowed_tags,
                           attributes=allowed_attrs,
                           strip=True)

    return cleaned


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return function(*args, **kwargs)

    return decorated_function


@app.route('/register', methods=["POST", "GET"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("get_all_posts"))
    form = RegisterForm()
    if form.validate_on_submit():
        # if form.email.data not in [user.email for user in db.session.execute(db.select(User)).scalars().all()]:
        if not db.session.execute(db.select(User).where(User.email == form.email.data)).scalar():
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=16)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("You have already signed up. Login instead")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("get_all_posts"))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("Incorrect Credentials")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()

    # To Check if the databases work as intended
    # parents = db.session.execute(db.select(User)).scalars().all()
    # for parent in parents:
    #     print(f"Parent ID: {parent.id}")
    #     for child in parent.posts:
    #         print(f"  Child ID: {child.id}")

    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    # form.comment.data = ""
    requested_post = db.get_or_404(BlogPost, post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Only logged in users can comment. Log in to do so")
            return redirect(url_for("login"))
        new_comment = Comment(
            author_id=current_user.id,
            post_id=requested_post.id,
            text=strip_invalid_html(form.comment.data)
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    return render_template("post.html", post=requested_post, form=form)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            author_id=current_user.id,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete-comment/<int:comment_id>")
def delete_comment(comment_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    if not (comment_to_delete.author_id == current_user.id or current_user.id == 1):
        return abort(403)
    post_to_return = db.get_or_404(BlogPost, comment_to_delete.post_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_to_return.id))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message("Password Reset Request", sender=os.getenv("My_Email_g"), recipients=[user.email],
                  body=f"Here is your password reset link: {url_for('reset_token', token=token, _external=True)}")
    mail.send(msg)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("get_all_posts"))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        send_reset_email(user)
        flash("An email has been sent to your email address. Click on the link in email to reset your password", "info")
    return render_template("reset-request.html", form=form)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for("get_all_posts"))
    user = User.verify_reset_token(token=token)
    if not user:
        flash("That is an invalid or expired token")
        return redirect(url_for("reset_request"))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=16)
        db.session.commit()
        flash("Your password has been reset!", "success")
        return redirect(url_for("login"))
    return render_template("reset-token.html", form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
