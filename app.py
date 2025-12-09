from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from markupsafe import escape
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret123"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///todo.db"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# --------------------------
# Database Models
# --------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(200), )

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --------------------------
# Routes
# --------------------------
@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")

        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for("register"))

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created! You can now log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("todo"))
        else:
            flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/todo", methods=["GET", "POST"])
@login_required
def todo():
    if request.method == "POST":
        task = request.form["task"]
        new_task = Todo(task=task, user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for("todo"))

    tasks = Todo.query.filter_by(user_id=current_user.id).all()
    return render_template("todo.html", tasks=tasks)


@app.route("/delete/<int:id>")
@login_required
def delete_task(id):
    task = Todo.query.get_or_404(id)

    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()

    return redirect(url_for("todo"))

@app.route("/insecure_login", methods=["GET", "POST"])
def insecure_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # ❌ RAW SQL (SQL INJECTION VULNERABILITY)
        query = f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"
        result = db.session.execute(query).fetchone()

        if result:
            return "Logged in (INSECURE!)"
        return "Invalid login (INSECURE!)"

    return '''
    <form method="POST">
        <input name="username" placeholder="Username">
        <input name="password" placeholder="Password">
        <button>Login</button>
    </form>
    '''
@app.route("/insecure_comment", methods=["GET", "POST"])
def insecure_comment():
    if request.method == "POST":
        comment = request.form["comment"]
        return f"You said: {comment}"   # ❌ vulnerable to XSS

    return '''
    <form method="POST">
        <input name="comment" placeholder="Write something...">
        <button>Submit</button>
    </form>
    '''
@app.route("/secure_login", methods=["GET", "POST"])
def secure_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # ✔ Parameterized ORM lookup (SAFE)
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return "Logged in SECURELY!"

        return "Invalid credentials"

    return '''
    <form method="POST">
        <input name="username" placeholder="Username">
        <input name="password" placeholder="Password">
        <button>Login</button>
    </form>
    '''
@app.route("/secure_comment", methods=["GET", "POST"])
def secure_comment():
    safe_comment = ""
    if request.method == "POST":
        safe_comment = escape(request.form["comment"])  # ✔ Prevents XSS
    return render_template("secure_comment.html", safe_comment=safe_comment)

if __name__ == "__main__":
    if not os.path.exists("todo.db"):
        with app.app_context():
            db.create_all()

    app.run(debug=True)


