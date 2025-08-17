from flask import Blueprint, render_template, request, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import Data, User
from flask_login import login_user, login_required, logout_user, current_user

views = Blueprint('views', __name__)

@views.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    data1 = Data.name
    return render_template("one.html", data=data1, user=current_user)
    

@views.route('/add-review', methods=['GET', 'POST'])
def view():
    if request.method == 'POST':
        name = request.values.get('name')
        review = request.form.get('review')#Gets the note from the HTML 

        if len(review) < 1:
            flash('Review is too short!', category='error') 
        else:
            new_review = Data(name=name, review=review)  #providing the schema for the note 
            db.session.add(new_review) #adding the note to the database 
            db.session.commit()
            flash('Note added!', category='success')
    data1 = Data.name
    return render_template("review.html", data=data1, user=current_user)


@views.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.login'))


@views.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

@views.route('/doctor1review', methods=['GET', 'POST'])
def doctor1review():
    reviews = Data.query.filter_by(name = "doctor1").all()
    if request.method == 'POST':
        review1 = request.form.get('review')#Gets the note from the HTML 
        if len(review1) < 1:
            flash('Review is too short!', category='error') 
        else:
            new_review = Data(name="doctor1", review=review1)  #providing the schema for the note 
            db.session.add(new_review) #adding the note to the database 
            db.session.commit()
            flash('Note added!', category='success')
    return render_template("doctor1review.html", reviews = reviews, user=current_user)

@views.route('/doctor2review', methods=['GET', 'POST'])
def doctor2review():
    reviews = Data.query.filter_by(name = "doctor2").all()
    if request.method == 'POST':
        review1 = request.form.get('review')#Gets the note from the HTML 
        if len(review1) < 1:
            flash('Review is too short!', category='error') 
        else:
            new_review = Data(name="doctor2", review=review1)  #providing the schema for the note 
            db.session.add(new_review) #adding the note to the database 
            db.session.commit()
            flash('Note added!', category='success')
    return render_template("doctor2review.html", reviews = reviews, user=current_user)

@views.route('/doctor3review', methods=['GET', 'POST'])
def doctor3review():
    reviews = Data.query.filter_by(name = "doctor3").all()
    if request.method == 'POST':
        review1 = request.form.get('review')#Gets the note from the HTML 
        if len(review1) < 1:
            flash('Review is too short!', category='error') 
        else:
            new_review = Data(name="doctor3", review=review1)  #providing the schema for the note 
            db.session.add(new_review) #adding the note to the database 
            db.session.commit()
            flash('Note added!', category='success')
    return render_template("doctor3review.html", reviews = reviews, user=current_user)