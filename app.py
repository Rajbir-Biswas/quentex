from flask import Flask, render_template, request, redirect
import sqlite3
import base64
import os
from qcrypto import encrypt, decrypt, KyberKEM

app = Flask(__name__)

DB = "pq_locker.db"

# Generate demo keypairs
alice_kem = KyberKEM()
alice_keys = alice_kem.generate_keypair()

bob_kem = KyberKEM()
bob_keys = bob_kem.generate_keypair()

alice_public = alice_keys.public_key
alice_private = alice_keys.private_key

bob_public = bob_keys.public_key
bob_private = bob_keys.private_key
keys = {
    "alice": (alice_public, alice_private),
    "bob": (bob_public, bob_private)
}


def init_db():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        recipient TEXT,
        ciphertext TEXT
    )
    """)

    conn.commit()
    conn.close()


@app.route("/", methods=["GET", "POST"])
def index():

    if request.method == "POST":

        sender = request.form["sender"]
        recipient = request.form["recipient"]
        message = request.form["message"]

        public_key = keys[recipient][0]

        ciphertext = encrypt(public_key, message.encode())

        conn = sqlite3.connect(DB)
        c = conn.cursor()

        c.execute(
            "INSERT INTO messages (sender, recipient, ciphertext) VALUES (?,?,?)",
            (sender, recipient, base64.b64encode(ciphertext).decode())
        )

        conn.commit()
        conn.close()

        return redirect("/")

    return render_template("index.html")


@app.route("/inbox/<user>")
def inbox(user):

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute(
        "SELECT id, sender FROM messages WHERE recipient=?",
        (user,)
    )

    messages = c.fetchall()

    conn.close()

    return render_template("inbox.html", user=user, messages=messages)


@app.route("/decrypt/<int:msg_id>")
def decrypt_msg(msg_id):

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute(
        "SELECT sender, recipient, ciphertext FROM messages WHERE id=?",
        (msg_id,)
    )

    data = c.fetchone()
    conn.close()

    sender = data[0]
    recipient = data[1]

    ciphertext = base64.b64decode(data[2])

    private_key = keys[recipient][1]

    plaintext = decrypt(private_key, ciphertext)

    return render_template(
        "message.html",
        sender=sender,
        plaintext=plaintext.decode()
    )


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
