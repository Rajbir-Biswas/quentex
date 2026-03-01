from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import oqs
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pq_locker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -----------------------
# Database Model
# -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    private_key = db.Column(db.LargeBinary, nullable=False)


# -----------------------
# Home Route
# -----------------------
@app.route("/")
def home():
    return "PQ Locker MVP is running"


# -----------------------
# Register Route
# -----------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data or "username" not in data:
        return jsonify({"error": "Username required"}), 400

    username = data["username"]

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    kem = oqs.KeyEncapsulation("Kyber512")
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()

    new_user = User(
        username=username,
        public_key=public_key,
        private_key=private_key
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"})


# -----------------------
# Get Public Key Route
# -----------------------
@app.route("/get_public_key/<username>", methods=["GET"])
def get_public_key(username):
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Encode binary key to base64 so it can be sent via JSON
    public_key_b64 = base64.b64encode(user.public_key).decode()

    return jsonify({
        "username": username,
        "public_key": public_key_b64
    })


# -----------------------
# Create DB + Run
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
