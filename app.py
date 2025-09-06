from flask import Flask, render_template, request
import sqlite3, os, qrcode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ------------------- Flask Setup -------------------
app = Flask(__name__)

# Ensure QR code folder exists
os.makedirs("static/qr_codes", exist_ok=True)

# Load keys
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# ------------------- Helper Functions -------------------
def sign_data(data: bytes):
    """Sign data using private key (ECDSA)."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

# ------------------- Database Setup -------------------
def init_db():
    conn = sqlite3.connect("products.db")
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY,
            name TEXT,
            manufacturer TEXT,
            expiry TEXT
        )"""
    )
    conn.commit()
    conn.close()

init_db()

# ------------------- Admin Route (QR Generator) -------------------
@app.route("/", methods=["GET", "POST"])
def home():
    qr_filename = None
    if request.method == "POST":
        product_id = request.form["product_id"]
        name = request.form["name"]
        manufacturer = request.form["manufacturer"]
        expiry = request.form["expiry"]

        # Save to DB
        conn = sqlite3.connect("products.db")
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO products VALUES (?, ?, ?, ?)",
                  (product_id, name, manufacturer, expiry))
        conn.commit()
        conn.close()

        # Create signature
        data = f"{product_id}|{name}|{manufacturer}|{expiry}".encode()
        signature = sign_data(data).hex()

        # Create QR code content
        qr_data = f"{product_id}|{name}|{manufacturer}|{expiry}|{signature}"

        # Save QR code
        qr_filename = f"{product_id}.png"
        qr_path = os.path.join("static/qr_codes", qr_filename)
        img = qrcode.make(qr_data)
        img.save(qr_path)

    return render_template("home.html", qr_filename=qr_filename)

# ------------------- Verify Route -------------------
@app.route("/verify", methods=["GET", "POST"])
def verify():
    result = None
    details = None

    if request.method == "POST":
        qr_data = request.form.get("qr_data", "")

        try:
            product_id, name, manufacturer, expiry, signature_hex = qr_data.split("|")

            # Recreate signed data
            data = f"{product_id}|{name}|{manufacturer}|{expiry}".encode()
            signature = bytes.fromhex(signature_hex)

            # Verify signature
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))

            # If valid, check DB
            conn = sqlite3.connect("products.db")
            c = conn.cursor()
            c.execute("SELECT id, name, manufacturer, expiry FROM products WHERE id=?", (product_id,))
            row = c.fetchone()
            conn.close()

            if row:
                result = "✅ Authentic Product"
                details = {"id": row[0], "name": row[1], "manufacturer": row[2], "expiry": row[3]}
            else:
                result = "⚠️ Product not found in database!"
        except Exception as e:
            print("Verification error:", e)
            result = "❌ Fake or Tampered Product!"

    return render_template("verify.html", result=result, details=details)

# ------------------- Run -------------------
if __name__ == "__main__":
    app.run(debug=True)
