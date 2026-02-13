"""
Python 后端漏洞演示服务器
包含常见的安全漏洞用于教育目的
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3
import os
import pickle
import subprocess
import hashlib

app = Flask(__name__)

# 数据库初始化
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

# ==================== 漏洞1: SQL注入 ====================
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # 漏洞: 直接拼接SQL语句
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"[DEBUG] SQL Query: {query}")  # 信息泄露

    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({"status": "success", "user": user[1], "role": user[3]})
        else:
            return jsonify({"status": "failed", "message": "Invalid credentials"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})  # 错误信息泄露

# ==================== 漏洞2: 命令注入 ====================
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '127.0.0.1')

    # 漏洞: 直接将用户输入拼接到系统命令
    command = f"ping -n 1 {host}"
    print(f"[DEBUG] Executing: {command}")

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return jsonify({"status": "success", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ==================== 漏洞3: 路径遍历 ====================
@app.route('/read', methods=['GET'])
def read_file():
    filename = request.args.get('file', 'readme.txt')

    # 漏洞: 未对路径进行验证，可使用 ../ 访问任意文件
    filepath = os.path.join('files', filename)
    print(f"[DEBUG] Reading file: {filepath}")

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"status": "success", "content": content})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ==================== 漏洞4: 不安全的反序列化 ====================
@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.data

    # 漏洞: 直接反序列化不可信数据
    try:
        obj = pickle.loads(data)
        return jsonify({"status": "success", "data": str(obj)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ==================== 漏洞5: 硬编码凭证 ====================
DATABASE_PASSWORD = "SuperSecretPass123!"  # 硬编码敏感信息
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "my-secret-key-12345"

@app.route('/config', methods=['GET'])
def get_config():
    # 漏洞: 暴露配置信息
    return jsonify({
        "db_host": "localhost",
        "db_password": DATABASE_PASSWORD,
        "api_key": API_KEY
    })

# ==================== 漏洞6: SSRF (服务器端请求伪造) ====================
import urllib.request

@app.route('/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url', 'http://example.com')

    # 漏洞: 未验证URL，可访问内部资源
    print(f"[DEBUG] Fetching URL: {url}")

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            content = response.read().decode('utf-8')
        return jsonify({"status": "success", "content": content[:500]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ==================== 漏洞7: 弱密码哈希 ====================
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # 漏洞: 使用MD5存储密码（弱哈希算法）
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

# ==================== 漏洞8: XSS (反射型) ====================
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')

    # 漏洞: 直接将用户输入返回到HTML中
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

# ==================== 漏洞9: 开放重定向 ====================
@app.route('/redirect', methods=['GET'])
def redirect_user():
    url = request.args.get('url', '/')

    # 漏洞: 未验证重定向目标
    from flask import redirect
    return redirect(url)

# ==================== 漏洞10: 信息泄露 ====================
@app.route('/debug', methods=['GET'])
def debug_info():
    # 漏洞: 暴露敏感系统信息
    return jsonify({
        "python_version": os.popen('python --version').read(),
        "environment": dict(os.environ),
        "current_directory": os.getcwd(),
        "users": os.popen('whoami').read()
    })

# ==================== 首页 ====================
@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "message": "Vulnerable Python Server - For Educational Purposes Only",
        "endpoints": [
            "POST /login - SQL Injection",
            "GET /ping?host=xxx - Command Injection",
            "GET /read?file=xxx - Path Traversal",
            "POST /deserialize - Insecure Deserialization",
            "GET /config - Hardcoded Credentials",
            "GET /fetch?url=xxx - SSRF",
            "POST /register - Weak Password Hash",
            "GET /search?q=xxx - Reflected XSS",
            "GET /redirect?url=xxx - Open Redirect",
            "GET /debug - Information Disclosure"
        ]
    })

if __name__ == '__main__':
    # 创建测试文件目录
    os.makedirs('files', exist_ok=True)
    with open('files/readme.txt', 'w') as f:
        f.write('This is a sample file for testing.')

    print("=" * 50)
    print("Vulnerable Python Server Started")
    print("For Educational Purposes Only!")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)
