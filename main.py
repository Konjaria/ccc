from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    # first become ensure that we would like to add a new record in the database
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login', logged_in=False))

        new_user = User(email=request.form.get('email'),
                        password=generate_password_hash(request.form.get('password')),
                        name=request.form.get('name'))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets', user_name=request.form.get('name'), logged_in=True))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    print('Worst than ever job man')
    err = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        # Check stored password hash against entered password hashed.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login', logged_in=False))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login', logged_in=False))
        else:
            login_user(user)
            return redirect(url_for('secrets', user_name=current_user.name, logged_in=True))

    return render_template("login.html", error=err)


@app.route('/secrets')
@login_required
def secrets():
    # We need to be ensured that the user is logged in to the website.
    return render_template("secrets.html", user_name=request.args.get('user_name'), logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    print(current_user.name)
    return send_from_directory('static/files', filename='cheat_sheet.pdf', as_attachment=False, logged_in=True)


if __name__ == "__main__":
    app.run(debug=True)
