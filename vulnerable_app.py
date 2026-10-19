"""
Aplicación web vulnerable simple para demostración educativa
Simula vulnerabilidades comunes que w3af detectaría
"""

from flask import Flask, request, render_template_string
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)

# Base de datos simple
DB_FILE = 'vulnerable.db'

def init_db():
    """Inicializa la base de datos con datos de prueba"""
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    c.execute("INSERT INTO users VALUES (1, 'admin', 'password123', 'admin@example.com')")
    c.execute("INSERT INTO users VALUES (2, 'user1', 'user1234', 'user1@example.com')")
    conn.commit()
    conn.close()

# Inicializar DB
if not os.path.exists(DB_FILE):
    init_db()

# ============ VULNERABILIDAD 1: SQL INJECTION ============
@app.route('/search', methods=['GET', 'POST'])
def search():
    """SQL Injection vulnerable endpoint"""
    query = request.args.get('q', '')
    results = []

    if query:
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            # VULNERABLE: construcción directa de SQL
            sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
            c.execute(sql)
            results = c.fetchall()
            conn.close()
        except Exception as e:
            results = [f"Error: {str(e)}"]

    html = """
    <h2>Búsqueda de Usuarios (VULNERABLE a SQL Injection)</h2>
    <form method='GET'>
        <input type='text' name='q' value='{query}' placeholder='Ingrese nombre de usuario'>
        <button type='submit'>Buscar</button>
    </form>
    <h3>Resultados:</h3>
    <pre>{results}</pre>
    <hr>
    <p style='color:red;'><b>Intenta:</b> ' OR '1'='1</p>
    """.format(query=query, results='\n'.join(str(r) for r in results))

    return render_template_string(html)

# ============ VULNERABILIDAD 2: XSS (Cross-Site Scripting) ============
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    """XSS vulnerable endpoint"""
    comments = []
    message = request.args.get('msg', '')

    if message:
        comments.append({
            'text': message,  # VULNERABLE: no se sanitiza
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    html = """
    <h2>Comentarios (VULNERABLE a XSS)</h2>
    <form method='GET'>
        <input type='text' name='msg' placeholder='Ingrese un comentario'>
        <button type='submit'>Comentar</button>
    </form>
    <h3>Comentarios:</h3>
    """

    for c in comments:
        html += f"<p><b>{c['time']}:</b> {c['text']}</p>"

    html += """
    <hr>
    <p style='color:red;'><b>Intenta:</b> &lt;img src=x onerror="alert('XSS Vulnerable!');"&gt;</p>
    """

    return render_template_string(html)

# ============ VULNERABILIDAD 3: Information Disclosure ============
@app.route('/debug')
def debug_info():
    """Información sensible expuesta"""
    info = {
        'app_version': '1.0.0',
        'database': DB_FILE,
        'python_version': '3.10',
        'secret_key': 'super_secret_key_12345',
        'admin_email': 'admin@vulnerable.com',
        'server_path': os.getcwd()
    }

    html = "<h2>Debug Info (VULNERABLE: Information Disclosure)</h2>"
    html += "<pre>"
    for key, value in info.items():
        html += f"{key}: {value}\n"
    html += "</pre>"

    return render_template_string(html)

# ============ VULNERABILIDAD 4: Weak Authentication ============
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login con credenciales débiles y sin protección"""
    user = request.args.get('user', '')
    password = request.args.get('pass', '')

    # Credenciales débiles conocidas
    weak_creds = {
        'admin': 'password123',
        'user1': 'user1234',
        'test': 'test'
    }

    message = ""
    if user and password:
        if user in weak_creds and weak_creds[user] == password:
            message = f"<p style='color:green;'>Bienvenido {user}!</p>"
        else:
            message = "<p style='color:red;'>Credenciales inválidas</p>"

    html = """
    <h2>Login (VULNERABLE: Weak Credentials, No HTTPS)</h2>
    <form method='GET'>
        <input type='text' name='user' placeholder='Usuario' value='{user}'>
        <input type='text' name='pass' placeholder='Contraseña'>
        <button type='submit'>Entrar</button>
    </form>
    {message}
    <hr>
    <p style='color:red;'><b>Credenciales débiles:</b></p>
    <ul>
        <li>admin / password123</li>
        <li>user1 / user1234</li>
        <li>test / test</li>
    </ul>
    """.format(user=user, message=message)

    return render_template_string(html)

# ============ PÁGINA PRINCIPAL ============
@app.route('/')
def index():
    html = """
    <html>
    <head><title>App Vulnerable - Demo</title></head>
    <body>
    <h1>Aplicación Web Vulnerable - Demostración Educativa</h1>
    <p>Esta aplicación contiene vulnerabilidades comunes para demostración.</p>
    <h2>Vulnerabilidades incluidas:</h2>
    <ul>
        <li><a href='/search'>SQL Injection</a></li>
        <li><a href='/comment'>Cross-Site Scripting (XSS)</a></li>
        <li><a href='/debug'>Information Disclosure</a></li>
        <li><a href='/login'>Weak Authentication</a></li>
        <li>Missing Security Headers</li>
    </ul>
    <hr>
    <p><small>Creada para demostración educativa de w3af</small></p>
    </body>
    </html>
    """
    return render_template_string(html)

@app.after_request
def remove_headers(response):
    """VULNERABLE: No se establecen headers de seguridad"""
    return response

if __name__ == '__main__':
    # Si corre dentro de un GitHub Codespace, GitHub expone cada puerto en una
    # URL pública tipo https://<codespace>-<puerto>.app.github.dev
    codespace_name = os.environ.get('CODESPACE_NAME')
    forwarding_domain = os.environ.get('GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN', 'app.github.dev')
    base_url = f"https://{codespace_name}-5000.{forwarding_domain}" if codespace_name else "http://127.0.0.1:5000"

    print("="*60)
    print("APLICACIÓN WEB VULNERABLE - PARA DEMOSTRACIÓN EDUCATIVA")
    print("="*60)
    print(f"\nIniciando en {base_url}/")
    if codespace_name:
        print("(Ejecutando en GitHub Codespaces: si el puerto 5000 aparece como")
        print(" privado en la pestaña 'Ports', cámbialo a 'Public' o 'Private' con")
        print(" tu sesión de GitHub para poder abrirlo en el navegador)")
    print("\nVulnerabilidades demostrables:")
    print(f"  1. SQL Injection: {base_url}/search")
    print(f"  2. XSS: {base_url}/comment")
    print(f"  3. Information Disclosure: {base_url}/debug")
    print(f"  4. Weak Authentication: {base_url}/login")
    print("\n" + "="*60 + "\n")

    # host='0.0.0.0' es necesario para que Codespaces/Docker puedan exponer el
    # puerto; en tu máquina local sigue siendo accesible por 127.0.0.1 igual.
    app.run(debug=False, host='0.0.0.0', port=5000)
