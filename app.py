from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import json
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta, SU
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, URLField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, URL, Optional
from flask_migrate import Migrate

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ideas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    affiliation = db.Column(db.String(100), nullable=True)
    linkedin = db.Column(db.String(200), nullable=True)
    ideas = db.relationship('Idea', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

class Idea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    hypothesis = db.Column(db.Text, nullable=False)
    proposed_user = db.Column(db.String(100), nullable=False)
    problem = db.Column(db.Text, nullable=False)
    proposed_solution = db.Column(db.Text)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    sunday_date = db.Column(db.DateTime, nullable=False)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='idea', lazy=True, cascade='all, delete-orphan')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    idea_id = db.Column(db.Integer, db.ForeignKey('idea.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    affiliation = StringField('School/Work', validators=[Optional(), Length(max=100)])
    linkedin = URLField('LinkedIn Profile', validators=[Optional(), URL()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UpdateProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    affiliation = StringField('School/Work', validators=[Optional(), Length(max=100)])
    linkedin = URLField('LinkedIn Profile', validators=[Optional(), URL()])
    submit = SubmitField('Update Profile')

class SubmitIdeaForm(FlaskForm):
    name = StringField('Idea Name', validators=[DataRequired(), Length(min=2, max=100)])
    hypothesis = TextAreaField('Hypothesis', validators=[DataRequired()])
    proposed_user = StringField('Target User', validators=[DataRequired(), Length(min=2, max=100)])
    problem = TextAreaField('Problem', validators=[DataRequired()])
    proposed_solution = TextAreaField('Proposed Solution', validators=[Optional()])
    submit = SubmitField('Submit Idea')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if user already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('An account with that email already exists. Please use a different email or login.', 'danger')
            return render_template('register.html', form=form)
            
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(
                email=form.email.data,
                password=hashed_password,
                name=form.name.data,
                affiliation=form.affiliation.data,
                linkedin=form.linkedin.data
            )
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'danger')
            print(f"Error creating user: {str(e)}")
            return render_template('register.html', form=form)
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.affiliation = form.affiliation.data
        current_user.linkedin = form.linkedin.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.name.data = current_user.name
        form.affiliation.data = current_user.affiliation
        form.linkedin.data = current_user.linkedin
    
    return render_template('edit_profile.html', form=form)

@app.route('/')
def home():
    sort_by = request.args.get('sort', 'recent')
    
    if sort_by == 'votes':
        ideas = Idea.query.order_by((Idea.upvotes - Idea.downvotes).desc()).all()
    else:
        ideas = Idea.query.order_by(Idea.submission_date.desc()).all()
    
    return render_template('index.html', ideas=ideas, sort_by=sort_by)

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    form = SubmitIdeaForm()
    if form.validate_on_submit():
        try:
            next_sunday = get_next_sunday()
            
            new_idea = Idea(
                name=form.name.data,
                hypothesis=form.hypothesis.data,
                proposed_user=form.proposed_user.data,
                problem=form.problem.data,
                proposed_solution=form.proposed_solution.data,
                sunday_date=next_sunday,
                user_id=current_user.id
            )
            
            db.session.add(new_idea)
            db.session.commit()
            
            flash('Your idea has been submitted successfully!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting your idea. Please try again.', 'danger')
            print(f"Error submitting idea: {str(e)}")
    
    return render_template('submit.html', form=form, next_sunday=get_next_sunday())

@app.route('/idea/<int:idea_id>')
def view_idea(idea_id):
    idea = Idea.query.get_or_404(idea_id)
    return render_template('idea.html', idea=idea)

@app.route('/comment/<int:idea_id>', methods=['POST'])
@login_required
def add_comment(idea_id):
    idea = Idea.query.get_or_404(idea_id)
    
    comment = Comment(
        content=request.form['content'],
        idea_id=idea_id,
        user_id=current_user.id if current_user.is_authenticated else None
    )
    
    db.session.add(comment)
    db.session.commit()
    
    return redirect(url_for('view_idea', idea_id=idea_id))

@app.route('/vote/<int:idea_id>/<vote_type>', methods=['POST'])
@login_required
def vote(idea_id, vote_type):
    idea = Idea.query.get_or_404(idea_id)
    
    if vote_type == 'up':
        idea.upvotes += 1
    elif vote_type == 'down':
        idea.downvotes += 1
    
    db.session.commit()
    return jsonify({'upvotes': idea.upvotes, 'downvotes': idea.downvotes})

@app.route('/admin')
@login_required
def admin():
    ideas = Idea.query.order_by(Idea.sunday_date).all()
    return render_template('admin.html', ideas=ideas)

@app.route('/admin/edit/<int:idea_id>', methods=['POST'])
@login_required
def admin_edit(idea_id):
    idea = Idea.query.get_or_404(idea_id)
    
    if request.form.get('sunday_date'):
        idea.sunday_date = parse(request.form['sunday_date'])
    
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/admin/delete/<int:idea_id>', methods=['POST'])
@login_required
def admin_delete(idea_id):
    idea = Idea.query.get_or_404(idea_id)
    
    # Delete all comments associated with this idea
    Comment.query.filter_by(idea_id=idea.id).delete()
    
    # Delete the idea
    db.session.delete(idea)
    
    try:
        db.session.commit()
        flash('Idea has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the idea.', 'danger')
        print(f"Error deleting idea: {str(e)}")
    
    return redirect(url_for('admin'))

@app.route('/calendar')
def calendar():
    ideas = Idea.query.all()
    # Convert ideas to a format that can be serialized to JSON
    ideas_json = [{
        'id': idea.id,
        'name': idea.name,
        'hypothesis': idea.hypothesis,
        'proposed_user': idea.proposed_user,
        'sunday_date': idea.sunday_date.isoformat() if idea.sunday_date else None
    } for idea in ideas]
    return render_template('calendar.html', ideas=ideas_json)

def get_next_sunday(from_date=None):
    if from_date is None:
        from_date = datetime.now()
    next_sunday = from_date + relativedelta(weekday=SU(1))
    return next_sunday.replace(hour=0, minute=0, second=0, microsecond=0)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8080)
