from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash,
)
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from datetime import datetime
import psycopg2
import qrcode
import io
import os
import base64
import random  # Add this at the top
import string  # Add this for alphanumeric OTPs (optional)
from database import get_db_connection
from utils import decode_qr_code
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

def generate_otp(length=4):
    return ''.join(random.choices(string.digits, k=length))
# Define the path for QR code images
QR_CODE_DIR = os.path.join("static", "qrcodes")

# Ensure the QR code directory exists
if not os.path.exists(QR_CODE_DIR):
    os.makedirs(QR_CODE_DIR)


# Function to generate QR code and save it as an image file
def generate_qr_code(data, author, date_created):
    qr_content = f"{data},{author},{date_created}"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_content)
    qr.make(fit=True)

    # Create an image of the QR code
    img = qr.make_image(fill="black", back_color="white")

    # Save the image to the static folder
    img_filename = f"{data.replace(' ', '_')}.png"
    img_path = os.path.join(QR_CODE_DIR, img_filename)
    img.save(img_path)

    # Return the URL to the saved QR code image
    return url_for("static", filename=f"qrcodes/{img_filename}")


@app.route("/compare_qr", methods=["POST"])
def compare_qr():
    uploaded_file = request.files["qr_image"]
    uploaded_path = os.path.join("static/temp", uploaded_file.filename)
    uploaded_file.save(uploaded_path)

    uploaded_content = decode_qr_code(uploaded_path)

    # Loop through existing QR codes in /static/qrcodes
    qr_dir = os.path.join("static", "qrcodes")
    for filename in os.listdir(qr_dir):
        file_path = os.path.join(qr_dir, filename)
        existing_content = decode_qr_code(file_path)

        if uploaded_content and uploaded_content == existing_content:
            return f"Match found with {filename}"

    return "No match found"


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
    otp = request.args.get("otp")
    conn = get_db_connection()
    cur = conn.cursor()
    
    if request.method == "POST":
        if request.form.get("action") == "Create":
            # Handle create user
            username = request.form["username"]
            address = request.form["address"]
            phone = request.form["phone"]
            to_borrow = request.form.get("to_borrow")  # Get selected file
            slot_number = request.form.get("slot_number")  # ✅ Get selected slot_number
            otp = generate_otp()  # 🔐 Generate OTP


            # Check if selected slot is available
            cur.execute(
                "SELECT is_available FROM user_slots WHERE slot_number = %s",
                (slot_number,),
            )
            slot = cur.fetchone()

            if not slot or not slot[0]:
                flash(
                    f"Slot {slot_number} is already taken. Please choose another.",
                    "error",
                )
                return redirect(url_for("users"))

            cur.execute(
                """
            INSERT INTO users 
            (username, address, phone, to_borrow, slot_number, otp)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
                (
                    username,
                    address,
                    phone,
                    to_borrow,
                    slot_number,
                    otp,  # Store OTP in the database
                ),
            )

            # Mark the slot as unavailable
            cur.execute(
                "UPDATE user_slots SET is_available = FALSE WHERE slot_number = %s",
                (slot_number,),
            )
            cur.execute("SELECT id FROM files WHERE name = %s", (to_borrow,))
            file = cur.fetchone()
            if file:
                file_id = file[0]
                cur.execute(
                    """
                INSERT INTO transactions (file_id, borrower_name, borrow_date, status, file_name)
                VALUES (%s, %s, %s, %s, %s)
                """,
                    (file_id, username, datetime.now(), "Borrowed", to_borrow),
                )
            conn.commit()
            return redirect(url_for("users", otp=otp))

    # GET method - display users and file options
    cur.execute("SELECT id, username, role FROM users")
    users = cur.fetchall()

    cur.execute(
        """
    SELECT id, name
    FROM files
    WHERE name NOT IN (
        SELECT to_borrow FROM users WHERE to_borrow IS NOT NULL AND to_borrow != ''
    )
    """
    )  # Get list of files
    file_options = cur.fetchall()
    cur.execute(
        "SELECT slot_number FROM user_slots WHERE is_available = TRUE ORDER BY slot_number ASC"
    )
    available_slots = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "users.html",
        active_page="users",
        username=current_user.username,
        users=users,
        file_options=file_options,
        available_slots=available_slots,
        generated_otp=otp,
    )


@app.route("/enroll_fingerprint", methods=["POST"])
def enroll_fingerprint():
    try:
        from pyfingerprint.pyfingerprint import PyFingerprint

        f = PyFingerprint("/dev/ttyUSB0", 57600, 0xFFFFFFFF, 0x00000000)
        if not f.verifyPassword():
            return jsonify(success=False)

        if f.readImage():
            f.convertImage(0x01)

            result = f.searchTemplate()
            positionNumber = result[0]

            if positionNumber >= 0:
                return jsonify(success=False)

            f.createTemplate()
            positionNumber = f.storeTemplate()

            return jsonify(success=True, fingerprint_id=positionNumber)
    except Exception as e:
        print("Error:", e)
        return jsonify(success=False)


@app.route("/api/fingerprint", methods=["POST"])
def fingerprint_api():
    data = request.get_json()
    finger_id = data.get("finger_id")

    if finger_id is not None:
        # You can log this, update a DB, etc.
        print(f"Received fingerprint match ID: {finger_id}")
        return jsonify({"message": "Fingerprint received", "id": finger_id}), 200
    else:
        return jsonify({"error": "No fingerprint ID provided"}), 400


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
            author = request.form.get("author")
            qr_code = generate_qr_code(name, author, datetime.now())

            cur.execute(
                "INSERT INTO files (name, file_type, qr_code, author, date_created) VALUES (%s, %s, %s,%s, NOW())",
                (name, file_type, qr_code, author),
            )
            conn.commit()
            flash("File created successfully!", "success")

        elif action == "Edit":
            file_id = request.form["file_id"]
            name = request.form["name"]
            file_type = request.form["file_type"]
            qr_code = generate_qr_code(name, author, datetime.now())

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


@app.route("/api/check_borrow", methods=["GET"])
def check_borrow():
    book_name = request.args.get("book_name")
    if not book_name:
        return jsonify({"error": "Missing book_name"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Find user who borrowed the book
    cur.execute("SELECT * FROM users WHERE to_borrow = %s", (book_name,))
    user = cur.fetchone()

    if user:
        user_id = user[0]  # Assuming 'id' is the first column in 'users'
        username = user[1]  # Assuming 'username' is the second column
        slot_number = user[5]  # Assuming 'slot_number' is the sixth column
        # Set return date to current timestamp
        return_date = datetime.now()
        # Update transaction status to "Returned"
        # Update the transaction to mark it as Returned and set return_date
        cur.execute(
            """
            UPDATE transactions
            SET status = 'Returned',
                return_date = %s
            WHERE borrower_name = %s AND status = 'Borrowed'
        """,
            (return_date, username),
        )

        # Mark the slot as available again
        cur.execute(
            """
            UPDATE user_slots
            SET is_available = TRUE
            WHERE slot_number = %s
        """,
            (slot_number,),
        )

        # Delete the user from the users table
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))

        conn.commit()
        cur.close()
        conn.close()

        return "found"
    else:
        cur.close()
        conn.close()
        return "not_found"


@app.route("/api/check_slot/<int:slot_number>", methods=["GET"])
def check_slot(slot_number):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT is_available FROM user_slots WHERE slot_number = %s AND is_available=true",
        (slot_number,),
    )
    result = cur.fetchone()
    cur.close()
    conn.close()

    if result is not None:
        return "is_available"
    else:
        return "is_not_available"


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
    app.run(host="0.0.0.0", port=5000, debug=True)
