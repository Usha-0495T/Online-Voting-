import os
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, RadioField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from wtforms.validators import Regexp
app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisshouldbeasecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Max upload 2MB

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}


# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200))
    aadhar_number = db.Column(db.String(12), unique=True)   # Store as string to preserve leading zeros
    document_filename = db.Column(db.String(200))
    voted = db.Column(db.Boolean, default=False)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    candidate = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=80)])
    confirm = PasswordField('Repeat Password', validators=[InputRequired(), EqualTo('password')])
       
    # Aadhaar Number: exactly 12 digits
    aadhar_number = StringField(
        'Aadhaar Number',
        validators=[
            InputRequired(),
            Regexp('^[0-9]{12}$', message="Aadhaar number must be exactly 12 digits")
        ]
    )
    document = FileField('Upload ID Proof (png/jpg/pdf)', validators=[InputRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class VoteForm(FlaskForm):
    candidate = RadioField('Select Candidate', choices=[('Candidate A', 'Candidate A'), ('Candidate B', 'Candidate B')], validators=[InputRequired()])
    submit = SubmitField('Vote')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists.')
            return redirect(url_for('register'))
        file = form.document.data
        if file and allowed_file(file.filename):
            filename = secure_filename(form.username.data + "_" + file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            new_user = User(username=form.username.data, password=hashed_password, aadhar_number=form.aadhar_number.data,document_filename=filename)
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully! Please log in.')
            return redirect(url_for('login'))
        else:
            flash('Invalid file type. Allowed types: png, jpg, jpeg, pdf.')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('vote'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('home'))

@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    if current_user.voted:
        flash('You have already voted.')
        return redirect(url_for('results'))
    form = VoteForm()
    if form.validate_on_submit():
        # Verify document exists before allowing to vote
        document_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.document_filename)
        if not os.path.exists(document_path):
            flash('Document verification failed. Contact support.')
            return redirect(url_for('logout'))
        # Cast the vote
        new_vote = Vote(candidate=form.candidate.data, user_id=current_user.id)
        db.session.add(new_vote)
        current_user.voted = True
        db.session.commit()
        flash('Your vote has been successfully recorded.')
        return redirect(url_for('results'))
    return render_template('vote.html', form=form)

@app.route('/results')
def results():
    votes = Vote.query.all()
    candidates = [c[0] for c in Vote.query.with_entities(Vote.candidate).distinct()]
    tally = {c: 0 for c in candidates}
    for vote in votes:
        tally[vote.candidate] = tally.get(vote.candidate, 0) + 1
    return render_template('results.html', results=tally)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # Secure serving of uploaded document files
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == "__main__":
    if not os.path.exists('uploads'):
        os.makedirs('uploads')

    with app.app_context():   # ✅ Ensure app context
        db.create_all()

    app.run(debug=True)
