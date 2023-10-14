from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired,Length, ValidationError
from datetime import datetime
from flask_bcrypt import Bcrypt
import sqlite3
import random
from time import sleep

import yagmail

yag = yagmail.SMTP('heslopd23', 'evgl hfmq pxrf hgnm')

app = Flask(__name__)
app.secret_key = b'_alld**(#)$MKajksd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = "Thisisasecretkey"
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username", "class": "form-control"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Password", "class": "form-control"})
    email = StringField(validators=[InputRequired()], render_kw={"placeholder": "Email", "type": "email", "class": "form-control"})
    submit = SubmitField("Register", render_kw={"class": "btn btn-primary"})

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("Username already exists!")
        
        
    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("Email already exists")

    

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username", "class": "form-control"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Password", "class": "form-control"})
    submit = SubmitField("Login", render_kw={"class": "btn btn-primary"})



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    # list of todos for that user
    todos = db.relationship('Todo', backref='user')


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False, unique=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # using a id as a foreignKey to show which user has it

    def __repr__(self):
        return '<Task %r>' % self.id

with app.app_context():
    db.create_all()

def printDB():
    conn = sqlite3.connect('instance/test.db')
    c = conn.cursor()
    print("USERS")
    res = c.execute("SELECT * FROM user")

    for y in res.fetchall():
        print(y)


@app.route('/')
def index():

    return render_template('index.html')


@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    # yag.send(to=["rylimitless@gmail.com","heslopd23@gmail.com"],subject="Testing", contents=["<h1>Hello World!</h1>", "Sorry... that was actually my bad. Im here trying to build a flask app and sending out emails with yagmail... but what did you use for your emails??", "This allows you to send html formatted emails... but I dont know what extent it is tho..."])
    printDB()
    flash("HEY!", "message")
    user_id = session['user_id']
    currentUser = User.query.filter_by(id=user_id).first()
    if request.method == 'POST':
        task_content = request.form['content']
        new_task = Todo(content=task_content, user = current_user)

        try:
            db.session.add(new_task)
            db.session().commit()
            return redirect('/dashboard')
        except:
            return "There was an issue adding your task"
        
    else:
        currentUser = User.query.filter_by(id=user_id).first()
        tasks = currentUser.todos
        # Todo.query.order_by(Todo.date_created).all()
        return render_template('dashboard.html', tasks=tasks)
        
@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/dashboard')
    except:
        return "There was an error"
    
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):

    task = Todo.query.get_or_404(id)

    if request.method == 'POST':
        task.content = request.form['content']

        try:
            db.session.commit()
            return redirect('/dashboard')

        except:
            return "There was an issue updating your task"
        
    else:
        return render_template('update.html', task=task)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    print("formyyyyyyyy")
    if request.method == "POST":
        value = form.validate_on_submit()
        print("VALIDATING")
        print(value)
        if value:
    

            user = User.query.filter_by(username=form.username.data).first()
            print("USER")
            print(user.__dict__)
            session['user_id'] = user.id
            print(session)
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    # print(current_user())
                    return redirect(url_for("dashboard"))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect('/login')



@app.route('/register',  methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if request.method == "POST":
        if form.validate_on_submit():
            print("SUBMITTED!!!!!!!!!!!!!!!!!!!!!!!")
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            email = form.email.data
            new_user = User(username=form.username.data, password=hashed_password, email=email)
            db.session.add(new_user)
            db.session().commit()
            # save user to db
            otp = random.randrange(100000, 1000000)
            session['otp'] = otp
            print("SEssion", session)
            htmlContent = f"""
                            <h1>Thanks for registering for our service!</h1>
                            <p>We have received a request for a OTP(one time password) to access your account. <br /> If you did not expect this email, please ignore it</p>
                            <p style='color:red'><b>NEVER</b> Share this password with anyone!</p>
                            <h2>Your OTP is <span style='color: purple;'>{otp}</span></h2>
    """
            yag.send(to=email,subject="Verify Your Login", contents=[htmlContent])
            return redirect(url_for('verify', email=email))        # # htmlContent = f"""
        #                     <h1>Thanks for registering for our service!</h1>
        #                     <p>We have received a request for a OTP(one time password) to access your account. If you did not expect this email, please ignore it</p>
        #                     <p style='color:red'><b>NEVER</b> Share this password with anyone!</p>
        #                     <h2>Your OTP is {123}</h2>"""
        # yag.send(subject="Verify Your Login", contents=[htmlContent])
    return render_template('register.html', form=form)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    sessionOTP = session.get('otp', None)
    email = request.args.get('email')

    if request.method == "GET":
        if sessionOTP:
            return render_template('verifyOTP.html', email=email)
        else:
            flash("You dont have access to this", "error")
            sleep(1)
            return redirect(url_for('/'))
    else:
        otp = request.form['otp']
        print("matched")
        if otp == sessionOTP:
            print("WELCOME!")
            session.pop('otp')
            return redirect(url_for('login'))
        flash("Incorrect OTP") 
    return render_template('verifyOTP.html', email=email)

if __name__ == "__main__":
    app.run(debug=True)
