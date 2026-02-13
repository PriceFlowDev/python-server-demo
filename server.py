"""
Python 后端服务器
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3
import os
import pickle
import subprocess
import hashlib
import urllib.request

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user123', 'user')")
    conn.commit()
    conn.close()

init_db()

DATABASE_PASSWORD = "SuperSecretPass123!"
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "my-secret-key-12345"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"[DEBUG] SQL Query: {query}")

    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({"status": "success", "user": user[1], "role": user[3]})
        else:
            return jsonify({"status": "failed", "message": "Invalid credentials"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '127.0.0.1')

    command = f"ping -n 1 {host}"
    print(f"[DEBUG] Executing: {command}")

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return jsonify({"status": "success", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/read', methods=['GET'])
def read_file():
    filename = request.args.get('file', 'readme.txt')

    filepath = os.path.join('files', filename)
    print(f"[DEBUG] Reading file: {filepath}")

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"status": "success", "content": content})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.data

    try:
        obj = pickle.loads(data)
        return jsonify({"status": "success", "data": str(obj)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/config', methods=['GET'])
def get_config():
    return jsonify({
        "db_host": "localhost",
        "db_password": DATABASE_PASSWORD,
        "api_key": API_KEY
    })

@app.route('/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url', 'http://example.com')

    print(f"[DEBUG] Fetching URL: {url}")

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            content = response.read().decode('utf-8')
        return jsonify({"status": "success", "content": content[:500]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       (username, hashed, 'user'))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": f"User {username} created"})
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)})

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')

    html = f"""
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <p>No results found.</p>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/redirect', methods=['GET'])
def redirect_user():
    url = request.args.get('url', '/')

    from flask import redirect
    return redirect(url)

@app.route('/debug', methods=['GET'])
def debug_info():
    return jsonify({
        "python_version": os.popen('python --version').read(),
        "environment": dict(os.environ),
        "current_directory": os.getcwd(),
        "users": os.popen('whoami').read()
    })

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "message": "Demo Python Server",
        "endpoints": [
            "POST /login",
            "GET /ping?host=xxx",
            "GET /read?file=xxx",
            "POST /deserialize",
            "GET /config",
            "GET /fetch?url=xxx",
            "POST /register",
            "GET /search?q=xxx",
            "GET /redirect?url=xxx",
            "GET /debug"
        ]
    })

if __name__ == '__main__':
    os.makedirs('files', exist_ok=True)
    with open('files/readme.txt', 'w') as f:
        f.write('This is a sample file for testing.')

    print("=" * 50)
    print("Python Server Started")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)
