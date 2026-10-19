#!/usr/bin/env python3
"""
Ejemplos de Vulnerabilidades - Sin servidor
Demostraciones de código vulnerable que simularía w3af
"""

print("="*70)
print("EJEMPLOS DE VULNERABILIDADES WEB - w3af Simulated")
print("="*70)

# ============================================================
# EJEMPLO 1: SQL INJECTION
# ============================================================
print("\n[1] SQL INJECTION VULNERABILITY")
print("-"*70)

print("\nCÓDIGO VULNERABLE:")
print("""
def search_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)  # VULNERABLE: concatenación directa
    return cursor.fetchall()
""")

print("\nCÓMO EXPLOTARLO:")
print("  Input normal: 'john'")
print("  SQL ejecutado: SELECT * FROM users WHERE name = 'john'")
print("")
print("  Input malicioso: \"' OR '1'='1")
print("  SQL ejecutado: SELECT * FROM users WHERE name = '' OR '1'='1'")
print("  Resultado: Devuelve TODOS los usuarios (La condición '1'='1' es siempre verdadera)")

print("\nIMPACTO:")
print("  - Acceso a datos confidenciales")
print("  - Modificación de datos")
print("  - Eliminación de bases de datos")
print("  - Ejecución de comandos del sistema (en algunos casos)")

print("\nREMEDIACIÓN:")
print("""
def search_user(username):
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (username,))  # Parámetros vinculados
    return cursor.fetchall()
""")

# ============================================================
# EJEMPLO 2: XSS (Cross-Site Scripting)
# ============================================================
print("\n\n[2] CROSS-SITE SCRIPTING (XSS) VULNERABILITY")
print("-"*70)

print("\nCÓDIGO VULNERABLE:")
print("""
def display_comment(comment_text):
    html = f"<p>{comment_text}</p>"  # VULNERABLE: sin sanitizar
    return html
""")

print("\nCÓMO EXPLOTARLO:")
print("  Input normal: 'Great article!'")
print("  HTML resultante: <p>Great article!</p>")
print("")
print("  Input malicioso: '<img src=x onerror=\"alert(\\'Hacked!\\')\">'")
print("  HTML resultante: <p><img src=x onerror=\"alert('Hacked!')\"></p>")
print("  Resultado: Se ejecuta JavaScript en el navegador de otros usuarios")

print("\nIMPACTO:")
print("  - Robo de cookies/sesiones")
print("  - Redirección a sitios maliciosos")
print("  - Modificación del contenido de la página")
print("  - Phishing")

print("\nREMEDIACIÓN:")
print("""
from markupsafe import escape

def display_comment(comment_text):
    html = f"<p>{escape(comment_text)}</p>"  # Sanitizar
    return html
""")

# ============================================================
# EJEMPLO 3: INFORMACIÓN DISCLOSURE
# ============================================================
print("\n\n[3] INFORMATION DISCLOSURE VULNERABILITY")
print("-"*70)

print("\nCÓDIGO VULNERABLE:")
print("""
@app.route('/debug')
def debug_info():
    return {
        'database_host': 'prod-db.internal.com',
        'api_key': 'sk_live_51234567890abcdef',
        'admin_email': 'admin@company.com',
        'server_version': 'Apache/2.4.41 (Ubuntu)',
        'python_version': '3.8.10'
    }
""")

print("\nQUÉ SE EXPONE:")
print("  - Detalles de infraestructura")
print("  - Credenciales y API keys")
print("  - Emails administrativos")
print("  - Versiones de software (útiles para encontrar exploits)")

print("\nIMPACTO:")
print("  - Información para otros ataques")
print("  - Social engineering")
print("  - Acceso no autorizado a sistemas")

print("\nREMEDIACIÓN:")
print("  - No exponer endpoints de debug")
print("  - Desactivar modo debug en producción")
print("  - Usar variables de entorno para secretos")
print("  - Minimizar detalles en mensajes de error")

# ============================================================
# EJEMPLO 4: WEAK AUTHENTICATION
# ============================================================
print("\n\n[4] WEAK AUTHENTICATION VULNERABILITY")
print("-"*70)

print("\nCÓDIGO VULNERABLE:")
print("""
WEAK_CREDENTIALS = {
    'admin': 'password123',
    'user1': 'user1234',
    'test': 'test'
}

def login(username, password):
    if username in WEAK_CREDENTIALS:
        if WEAK_CREDENTIALS[username] == password:
            return authenticate_user(username)
    return False
""")

print("\nCÓMO EXPLOTARLO:")
print("  Fuerza bruta contra credenciales comunes:")
common_passwords = ['password', '123456', 'admin', 'letmein', 'welcome']
print(f"  Contraseñas comunes: {', '.join(common_passwords)}")

print("\nIMPACTO:")
print("  - Acceso no autorizado")
print("  - Robo de datos")
print("  - Modificación de cuentas")
print("  - Impersonación de usuarios")

print("\nREMEDIACIÓN:")
print("""
import bcrypt

# Hash seguro de contraseñas
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verificar
bcrypt.checkpw(password.encode(), hashed)

# Políticas:
# - Mínimo 12 caracteres
# - Mezcla de mayúsculas, minúsculas, números, símbolos
# - Sin palabras comunes
# - Expiración periódica
# - Rate limiting en login
# - Autenticación multi-factor (MFA)
""")

# ============================================================
# EJEMPLO 5: MISSING SECURITY HEADERS
# ============================================================
print("\n\n[5] MISSING SECURITY HEADERS VULNERABILITY")
print("-"*70)

print("\nHEADERS RECOMENDADOS:")
headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'",
    'Referrer-Policy': 'no-referrer'
}

for header, value in headers.items():
    print(f"  {header}: {value}")

print("\nQUÉ PROTEGE CADA UNO:")
print("  X-Content-Type-Options: Previene MIME-type sniffing")
print("  X-Frame-Options: Previene clickjacking")
print("  X-XSS-Protection: Protección adicional contra XSS")
print("  Strict-Transport-Security: Fuerza HTTPS")
print("  Content-Security-Policy: Control de recursos cargados")
print("  Referrer-Policy: Privacidad de referrer")

print("\nREMEDIACIÓN EN FLASK:")
print("""
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
""")

# ============================================================
# TABLA RESUMEN
# ============================================================
print("\n\n[RESUMEN] MATRIZ DE VULNERABILIDADES")
print("="*70)

summary = """
┌────────────────────────┬──────────┬────────────────────────────┐
│ Vulnerabilidad         │ Severidad│ Cómo Detectarla             │
├────────────────────────┼──────────┼────────────────────────────┤
│ SQL Injection          │ CRÍTICA  │ Prueba payloads SQL        │
│                        │          │ Analiza mensajes de error   │
├────────────────────────┼──────────┼────────────────────────────┤
│ XSS                    │ ALTA     │ Inyecta scripts            │
│                        │          │ Verifica reflexión en HTML  │
├────────────────────────┼──────────┼────────────────────────────┤
│ Information Disclosure │ MEDIA    │ Escanea endpoints sensibles│
│                        │          │ Busca palabras clave       │
├────────────────────────┼──────────┼────────────────────────────┤
│ Weak Authentication    │ CRÍTICA  │ Prueba credenciales débiles│
│                        │          │ Fuerza bruta              │
├────────────────────────┼──────────┼────────────────────────────┤
│ Missing Sec Headers    │ BAJA     │ Analiza respuesta HTTP     │
│                        │          │ Verifica headers           │
└────────────────────────┴──────────┴────────────────────────────┘
"""
print(summary)

# ============================================================
# CONCLUSIÓN
# ============================================================
print("\n[CONCLUSIÓN]")
print("-"*70)
print("""
w3af y herramientas similares automatizan la detección de estas
vulnerabilidades combinando:

1. Crawling automático de la aplicación
2. Inyección de payloads de prueba
3. Análisis de respuestas
4. Generación de reportes

Esto que vimos manualmente, w3af lo hace automáticamente a través
de sus plugins de auditoría y explotación.

Para defensa:
- Validar TODA entrada de usuarios
- Sanitizar output
- Usar frameworks seguros
- Implementar security headers
- Hacer testing de seguridad regularmente
- Mantener dependencias actualizadas
""")

print("\n" + "="*70)
print("FIN DE EJEMPLOS")
print("="*70)
