import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

from time import time
from flask import Flask, jsonify, request, send_file
import sqlite3, socket, ast, csv, os
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.get("/")
def home():
    return ("<h1>Hello</h1>")

@app.get("/decode")
def decode():
    Json = request.get_json()
    encrypted = Json["encrypted"]
    hash = Json["hash"]
    decrypted = decrypt_AES_CBC_256("0123456789010123", encrypted)
    if verify_hash(decrypted,hash):
        data = ast.literal_eval(decrypted)
        return jsonify({"status":"Data is saved to db"})
    else:
        return jsonify({"status":"Data compromised not saved to db"})

def decrypt_AES_CBC_256(key, ciphertext):
    key_bytes = key.encode('utf-8')
    ciphertext_bytes = b64decode(ciphertext)
    iv = ciphertext_bytes[:AES.block_size]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ciphertext_bytes = ciphertext_bytes[AES.block_size:]
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)
    plaintext_bytes = unpad(decrypted_bytes, AES.block_size)
    plaintext = plaintext_bytes.decode('utf-8')
    return plaintext

def verify_hash(decrypted,hash):
    newHash = hashlib.sha256(decrypted.encode('utf-8')).hexdigest()
    if newHash == hash:
        print("Security Status: Data received securely!!")
        return True
    else:
        print("Security Status: Data is tampered with!!")
        return False

if __name__ == "__main__":
    app.debug=True
    # IPAddr = socket.gethostbyname(socket.gethostname())  
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8",80))
    IPAddr = s.getsockname()[0]
    app.run(host=IPAddr, port=5000)