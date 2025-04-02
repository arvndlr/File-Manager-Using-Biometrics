from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
import psycopg2
import qrcode
import io
import os
import base64
from database import get_db_connection
from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if user:
        return User(user[0], user[1], user[2])  # Return role as well
    return None


# Define the path for QR code images
QR_CODE_DIR = os.path.join("static", "qrcodes")

# Ensure the QR code directory exists
if not os.path.exists(QR_CODE_DIR):
    os.makedirs(QR_CODE_DIR)


# Function to generate QR code and save it as an image file
def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    # Create an image of the QR code
    img = qr.make_image(fill="black", back_color="white")

    # Save the image to the static folder
    img_filename = f"{data.replace(' ', '_')}.png"
    img_path = os.path.join(QR_CODE_DIR, img_filename)
    img.save(img_path)

    # Return the URL to the saved QR code image
    return url_for("static", filename=f"qrcodes/{img_filename}")


@app.route("/")
@login_required
def home():
    return render_template(
        "home.html", active_page="home", username=current_user.username
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password, role FROM users WHERE username = %s",
            (username,),
        )
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and bcrypt.check_password_hash(user[2], password):
            login_user(User(user[0], user[1], user[3]))  # Pass role as user[3]
            session["role"] = user[3]  # Store role in session

            flash("Login successful!", "success")

            # Redirect based on role
            if user[3] == "admin":
                return redirect(url_for("home"))  # Admin dashboard
            else:
                return redirect(url_for("client_files"))  # Client file borrowing page
        else:
            flash("Invalid credentials!", "danger")

    return render_template(
        "login.html",
        active_page="login",
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out!", "success")
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Check if username already exists
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            flash("Username already taken!", "danger")
            cur.close()
            conn.close()
            return redirect(url_for("signup"))

        # Insert new user into the database
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                (username, hashed_password, role),
            )
            conn.commit()
            flash("Account created successfully!", "success")
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")  # Show error as a toast message
        finally:
            cur.close()
            conn.close()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/history")
def history():
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch transaction history with the file name
    cur.execute(
        """
        SELECT transactions.id, files.name AS file_name, transactions.borrower_name, 
               transactions.borrow_date, transactions.return_date, transactions.status
        FROM transactions
        LEFT JOIN files ON transactions.file_id = files.id
        ORDER BY transactions.borrow_date DESC;
        """
    )

    history = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "history.html",
        active_page="history",
        username=current_user.username,
        history=history,
    )


@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    if request.method == "POST":
        if request.form.get("action") == "Create":
            # Handle create user
            username = request.form["username"]
            password = request.form["password"]
            role = request.form["role"]  # Add role from the form
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                (username, hashed_password, role),
            )
            conn.commit()
            cur.close()
            conn.close()
            flash("User created successfully!", "success")
            return redirect(url_for("users"))
        elif request.form.get("action") == "Edit":
            # Handle edit user
            user_id = request.form["user_id"]
            username = request.form["username"]
            password = request.form["password"]
            role = request.form["role"]  # Handle role change
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET username = %s, password = %s, role = %s WHERE id = %s",
                (username, hashed_password, role, user_id),
            )
            conn.commit()
            cur.close()
            conn.close()
            flash("User updated successfully!", "success")
            return redirect(url_for("users"))

    # Get all users to display in table
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users")
    users = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "users.html", active_page="users", username=current_user.username, users=users
    )


# Route to delete a user
@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    flash("User deleted successfully!", "success")
    return redirect(url_for("users"))


@app.route("/files", methods=["GET", "POST"])
@login_required
def files():
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        action = request.form.get("action")
        if action == "Create":
            name = request.form["name"]
            file_type = request.form["file_type"]
            qr_code = generate_qr_code(name + "-" + file_type)

            cur.execute(
                "INSERT INTO files (name, file_type, qr_code, date_created) VALUES (%s, %s, %s, NOW())",
                (name, file_type, qr_code),
            )
            conn.commit()
            flash("File created successfully!", "success")

        elif action == "Edit":
            file_id = request.form["file_id"]
            name = request.form["name"]
            file_type = request.form["file_type"]
            qr_code = generate_qr_code(name + "-" + file_type)

            cur.execute(
                "UPDATE files SET name = %s, file_type = %s, qr_code = %s WHERE id = %s",
                (name, file_type, qr_code, file_id),
            )
            conn.commit()
            flash("File updated successfully!", "success")

        elif action == "Delete":
            file_id = request.form["file_id"]
            cur.execute("DELETE FROM files WHERE id = %s", (file_id,))
            conn.commit()
            flash("File deleted successfully!", "success")

    cur.execute("SELECT id, name, file_type, qr_code, date_created FROM files")
    files = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "files.html", active_page="files", files=files, username=current_user.username
    )


@app.route("/borrow", methods=["POST"])
@login_required
def borrow_file():
    conn = get_db_connection()
    cur = conn.cursor()

    file_id = request.form["file_id"]
    borrower_name = current_user.username  # Assuming user authentication is in place

    # Fetch the file name from the files table based on file_id
    cur.execute("SELECT name FROM files WHERE id = %s", (file_id,))
    file_name = cur.fetchone()[0]  # Get the file name from the result

    # Insert borrow transaction, including the file_name
    cur.execute(
        """
        INSERT INTO transactions (file_id, file_name, borrower_name, status)
        VALUES (%s, %s, %s, 'Borrowed')
        """,
        (file_id, file_name, borrower_name),
    )
    conn.commit()

    flash("File borrowed successfully!", "success")
    cur.close()
    conn.close()
    return redirect(url_for("client_files"))


@app.route("/return", methods=["POST"])
@login_required
def return_file():
    conn = get_db_connection()
    cur = conn.cursor()

    transaction_id = request.form["transaction_id"]

    # Update return date and status
    cur.execute(
        "UPDATE transactions SET return_date = NOW(), status = 'Returned' WHERE id = %s",
        (transaction_id,),
    )
    conn.commit()

    flash("File returned successfully!", "success")
    cur.close()
    conn.close()
    return redirect(url_for("client_files"))


@app.route("/client_files")
@login_required
def client_files():
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch the list of available files from the database
    cur.execute("SELECT id, name, file_type, qr_code, date_created FROM files")
    files = cur.fetchall()  # List of available files

    # Fetch the list of borrowed files (from transactions table)
    cur.execute(
        """
        SELECT transactions.id, files.name, files.file_type, transactions.borrow_date
        FROM transactions
        JOIN files ON transactions.file_id = files.id
        WHERE transactions.borrower_name = %s AND transactions.status = 'Borrowed'
        """,
        (current_user.username,),
    )
    borrowed_files = cur.fetchall()  # List of borrowed files for the current user

    cur.close()
    conn.close()

    # Pass both available files and borrowed files to the template
    return render_template(
        "client_files.html",
        username=current_user.username,
        files=files,
        borrowed_files=borrowed_files,
    )


if __name__ == "__main__":
    app.run(debug=True)
