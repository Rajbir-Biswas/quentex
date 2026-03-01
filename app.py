from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

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
    return """
    <h2>PQ Locker Demo</h2>

    <h3>Register User</h3>
    <input id="reg_username" placeholder="Username">
    <button onclick="register()">Register</button>

    <h3>Encrypt Message</h3>
    <input id="enc_recipient" placeholder="Recipient">
    <input id="enc_message" placeholder="Message">
    <button onclick="encrypt()">Encrypt</button>

    <h3>Decrypt Message</h3>
    <input id="dec_username" placeholder="Username">
    <textarea id="dec_ciphertext" placeholder="Ciphertext"></textarea>
    <textarea id="dec_nonce" placeholder="Nonce"></textarea>
    <textarea id="dec_kem" placeholder="KEM Ciphertext"></textarea>
    <button onclick="decrypt()">Decrypt</button>

    <h3>Output</h3>
    <pre id="output"></pre>

    <script>
    async function register() {
        let username = document.getElementById("reg_username").value;
        let res = await fetch("/register", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({username})
        });
        let data = await res.json();
        document.getElementById("output").innerText = JSON.stringify(data, null, 2);
    }

    async function encrypt() {
        let recipient = document.getElementById("enc_recipient").value;
        let message = document.getElementById("enc_message").value;

        let res = await fetch("/encrypt", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({recipient, message})
        });

        let data = await res.json();
        document.getElementById("output").innerText = JSON.stringify(data, null, 2);
    }

    async function decrypt() {
        let username = document.getElementById("dec_username").value;
        let ciphertext = document.getElementById("dec_ciphertext").value;
        let nonce = document.getElementById("dec_nonce").value;
        let kem_ciphertext = document.getElementById("dec_kem").value;

        let res = await fetch("/decrypt", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({username, ciphertext, nonce, kem_ciphertext})
        });

        let data = await res.json();
        document.getElementById("output").innerText = JSON.stringify(data, null, 2);
    }
    </script>
    """

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

    #kem = oqs.KeyEncapsulation("Kyber512")
    #public_key = kem.generate_keypair()
    #private_key = kem.export_secret_key()

    new_user = User(
        username=username,
        public_key=public_key,
        private_key=private_key
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"})


# -----------------------
# Get Public Key
# -----------------------
@app.route("/get_public_key/<username>", methods=["GET"])
def get_public_key(username):
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    public_key_b64 = base64.b64encode(user.public_key).decode()

    return jsonify({
        "username": username,
        "public_key": public_key_b64
    })


# -----------------------
# Encrypt Message
# -----------------------
@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()

    recipient = data.get("recipient")
    message = data.get("message")

    if not recipient or not message:
        return jsonify({"error": "Recipient and message required"}), 400

    user = User.query.filter_by(username=recipient).first()
    if not user:
        return jsonify({"error": "Recipient not found"}), 404

    #kem = oqs.KeyEncapsulation("Kyber512")
    #ciphertext_kem, shared_secret = kem.encap_secret(user.public_key)

    aes_key = shared_secret[:32]
    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

    return jsonify({
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
     #   "kem_ciphertext": base64.b64encode(ciphertext_kem).decode()
    })


# -----------------------
# Decrypt Message
# -----------------------
@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()

    username = data.get("username")
    ciphertext = base64.b64decode(data.get("ciphertext"))
    nonce = base64.b64decode(data.get("nonce"))
    #kem_ciphertext = base64.b64decode(data.get("kem_ciphertext"))

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Initialize KEM with stored private key
    #kem = oqs.KeyEncapsulation("Kyber512", secret_key=user.private_key)

    #shared_secret = kem.decap_secret(kem_ciphertext)

    aes_key = shared_secret[:32]
    aesgcm = AESGCM(aes_key)

    decrypted_message = aesgcm.decrypt(nonce, ciphertext, None)

    return jsonify({
        "message": decrypted_message.decode()
    })

# -----------------------
# Run App
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
