from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)


da_login_manager = LoginManager()


# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("SQL_ALCHEMY_DATABASE_URI", "sqlite:///bbbb_posts.db")
# SQL_ALCHEMY_DATABASE_URI contains the URL pointing to the online database.
# sqlite:///bbbb_posts.db is the fallback URL to use if SQL_ALCHEMY_DATABASE_URI is not found,
# so the default is to use the local database stored on the PC which is handy for testing.
db = SQLAlchemy(model_class=Base)
db.init_app(app)

da_login_manager.init_app(app)

da_login_manager.login_view = "login"
# Specifies the route where users should be redirected if they try to access a protected page without logging in.

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES

class BlogPost(db.Model):

    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("RegisteredUsers", back_populates="posts")
    comments = relationship("Comments", back_populates="parent_post")
    # Basically, a variable, main purpose of which is - to establish connection between two databases.
    # Later it becomes possible to use variables from different databases, using those variables.
    # Through "back_populates" a connection between the two is established.
    # BUT! A foreign_key is imperative for the relationship to work! (Like one database inheriting the value of the variable from another)


class RegisteredUsers(UserMixin, db.Model):

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(1000), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="author_post")
    # About relationship:

    # First arg points to the "class" name.
    # Second argument points to the DB table name.
    # back_populates Indicates the name of a relationship() on the related class that will be synchronized with this one.


class Comments(db.Model):

    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(String(2000), nullable=False)
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author_post = relationship("RegisteredUsers", back_populates="comments")


def admin_only(da_function):
    @wraps(da_function)
    def da_decor_function(*args, **kwargs):

        if current_user.id != 1:
                return abort(403)

        return da_function(*args, **kwargs)
    return da_decor_function


with app.app_context():
    db.create_all()


@da_login_manager.user_loader
def load_user(user_id):
    return db.session.get(RegisteredUsers, user_id)



@app.route('/register', methods=["GET", "POST"])
def register():

    da_form = RegisterForm()

    if request.method == "POST":

        da_user_password = request.form["password"]
        da_user_email = request.form["email"]
        da_user_name = request.form["name"]

        da_result = db.session.execute(db.select(RegisteredUsers).where(RegisteredUsers.email == da_user_email))

        da_user = da_result.scalar()

        if da_user is not None:

            flash("That email already exists")

            return redirect("/register")

        da_hashed_password = generate_password_hash(da_user_password, method="pbkdf2:sha256", salt_length=6020)


        da_new_user = RegisteredUsers(
            email=da_user_email,
            password=da_hashed_password,
            name=da_user_name,
        )

        db.session.add(da_new_user)

        db.session.commit()

        login_user(da_new_user)

        return redirect("/")

    return render_template("register.html", form=da_form)


@app.route('/login', methods=["GET", "POST"])
def login():

    login_form = LoginForm()

    if request.method == "POST":

        da_password = request.form["password"]
        da_email = request.form["email"]

        da_result = db.session.execute(db.select(RegisteredUsers).where(RegisteredUsers.email == da_email))

        da_user = da_result.scalar()

        if da_user and check_password_hash(da_user.password, da_password):

            login_user(da_user)

            return redirect("/")

        elif da_user is None:

            flash("That email doesn't exist")

            return redirect("/login")

        elif check_password_hash(da_user.password, da_password) is False:

            flash("Incorrect password")

            return redirect("/login")

    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():

    logout_user()

    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():

    posts = []

    result = db.session.query(RegisteredUsers).all()

    for da_response in result:
        for da_blog in da_response.posts:
            posts.append(da_blog)


    try:
        return render_template("index.html",
                           all_posts=posts,
                           logged_in=current_user.is_authenticated,
                           da_id=current_user.id)
    except AttributeError:

        return render_template("index.html",
                               all_posts=posts,
                               logged_in=False)

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):

    da_form = CommentForm()

    requested_post = db.get_or_404(BlogPost, post_id)

    all_comments = db.session.execute(db.select(Comments).where(Comments.post_id == post_id)).all()


    if da_form.validate_on_submit():

        da_comment = da_form.commento.data

        da_new_comment = Comments(
            text=da_comment,
            author_post=current_user,
            parent_post = requested_post # Can use both relational parameters and IDs.
        )

        db.session.add(da_new_comment)

        db.session.commit()

    try:
        return render_template("post.html", post=requested_post,
                           logged_in=current_user.is_authenticated,
                           form=da_form,
                           da_id=current_user.id,
                           da_comments=all_comments,
                           da_gravatar=gravatar)
    except AttributeError:

        return render_template("post.html", post=requested_post,
                               logged_in=False,
                               form=da_form,
                               da_comments=all_comments)



@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)



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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)




@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=False, port=5002)

# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
