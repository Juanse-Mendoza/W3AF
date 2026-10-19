# Demostración Educativa de w3af - Guía de Clase

## Descripción General

Esta demostración muestra cómo w3af (Web Application Attack and Audit Framework) detecta vulnerabilidades web comunes. Incluye:

1. **vulnerable_app.py** - Aplicación web con vulnerabilidades intencionadas
2. **web_audit_scanner.py** - Script de auditoría que simula funcionalidad de w3af
3. Esta guía

## Requisitos

```bash
pip install flask requests
```

## Estructura de Archivos

```
.
├── vulnerable_app.py        # App vulnerable
├── web_audit_scanner.py     # Scanner educativo
└── README.md                # Esta guía
```

## Cómo Ejecutar

### Opción A: GitHub Codespaces (sin instalar nada local)

1. En GitHub, botón verde **Code** → pestaña **Codespaces** → **Create codespace on main**
2. Espera a que termine `postCreateCommand` (instala Flask y requests automáticamente)
3. Terminal 1: `python vulnerable_app.py`
4. Terminal 2: `python web_audit_scanner.py`
5. Cuando aparezca la notificación de puerto forwardeado (5000 y luego 8090), haz click en **Open in Browser**. Si no aparece, abre la pestaña **Ports** en VS Code y haz click en el ícono del globo junto al puerto correspondiente.

> Nota: por defecto los puertos forwardeados en Codespaces son privados a tu cuenta de GitHub (necesitas estar logueado para verlos); no hace falta hacerlos públicos para esta demo.

### Opción B: Local

### Paso 1: Iniciar la Aplicación Vulnerable

```bash
python vulnerable_app.py
```

Salida esperada:
```
============================================================
APLICACIÓN WEB VULNERABLE - PARA DEMOSTRACIÓN EDUCATIVA
============================================================

Iniciando en http://127.0.0.1:5000/

Vulnerabilidades demostrables:
  1. SQL Injection: http://127.0.0.1:5000/search
  2. XSS: http://127.0.0.1:5000/comment
  3. Information Disclosure: http://127.0.0.1:5000/debug
  4. Weak Authentication: http://127.0.0.1:5000/login

============================================================
```

### Paso 2: Ejecutar el Scanner en otra terminal

```bash
python web_audit_scanner.py
```

O especificar URL:
```bash
python web_audit_scanner.py http://127.0.0.1:5000
```

## Vulnerabilidades Demostradas

### 1. SQL Injection (Crítica)
**Endpoint:** `/search`

**Descripción:** La aplicación construye queries SQL directamente con entrada del usuario sin validar.

**Demostración manual:**
- Ir a: `http://127.0.0.1:5000/search`
- Campo: `' OR '1'='1`
- Resultado: Devuelve todos los usuarios (SQL injection exitoso)

**En el código:**
```python
sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"  # VULNERABLE
c.execute(sql)
```

**Remediación:**
```python
sql = "SELECT * FROM users WHERE username LIKE ?"
c.execute(sql, (f'%{query}%',))  # Parámetros vinculados
```

---

### 2. Cross-Site Scripting (XSS) (Alta)
**Endpoint:** `/comment`

**Descripción:** Los comentarios se muestran sin sanitizar, permitiendo inyectar JavaScript.

**Demostración manual:**
- Ir a: `http://127.0.0.1:5000/comment`
- Campo: `<img src=x onerror="alert('XSS Vulnerable!');">`
- Resultado: Se ejecuta el JavaScript

**En el código:**
```python
html += f"<p><b>{c['time']}:</b> {c['text']}</p>"  # VULNERABLE - texto sin sanitizar
```

**Remediación:**
```python
from markupsafe import escape
html += f"<p><b>{c['time']}:</b> {escape(c['text'])}</p>"
```

---

### 3. Information Disclosure (Media)
**Endpoint:** `/debug`

**Descripción:** Endpoint que expone información sensible del servidor.

**Qué se expone:**
- Versión de la aplicación
- Path del servidor
- Información de base de datos
- Secret keys
- Email de admin

**En el código:**
```python
info = {
    'secret_key': 'super_secret_key_12345',  # VULNERABLE
    'server_path': os.getcwd(),               # VULNERABLE
    'admin_email': 'admin@vulnerable.com'     # VULNERABLE
}
```

**Remediación:**
- No exponer información sensible
- Desactivar modo debug en producción
- Usar variables de entorno para secretos

---

### 4. Weak Authentication (Crítica)
**Endpoint:** `/login`

**Descripción:** Credenciales débiles y fáciles de adivinar.

**Credenciales vulnerables:**
- admin / password123
- user1 / user1234
- test / test

**Demostración manual:**
- Ir a: `http://127.0.0.1:5000/login?user=admin&pass=password123`
- Resultado: Acceso otorgado

**Remediación:**
- Implementar política de contraseñas fuerte
- Hash de contraseñas (bcrypt, argon2)
- Rate limiting en login
- Autenticación multi-factor (MFA)

---

### 5. Missing Security Headers (Baja)
**Descripción:** Ausencia de headers HTTP de seguridad importantes.

**Headers faltantes:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security`
- `Content-Security-Policy`

**Remediación:**
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

## Flujo de Clase Sugerido

### Parte 1: Presentación (5-10 min)
1. Explicar qué es w3af
2. Mostrar la importancia de testing de seguridad
3. Explicar las 5 vulnerabilidades a demostrar

### Parte 2: Demostración Interactiva (15-20 min)
1. Arrancar `vulnerable_app.py`
2. Mostrar cada vulnerabilidad manualmente en el navegador
3. Ejecutar `web_audit_scanner.py`
4. Analizar los resultados

### Parte 3: Análisis Profundo (15-20 min)
1. Revisar el código vulnerable en cada endpoint
2. Explicar el problema
3. Mostrar la remediación
4. Discutir impacto y severidad

### Parte 4: Discussión (10 min)
- Herramientas reales: Burp Suite, OWASP ZAP, w3af
- Buenas prácticas de seguridad
- Testing en SDLC

## Salida del Scanner Esperada

```
======================================================================
INICIANDO ESCANEO WEB - 2024-10-01 19:12:00
Objetivo: http://127.0.0.1:5000
======================================================================

[1] Buscando vulnerabilidades de SQL Injection...
  [VULNERABLE] SQL Injection detectada en http://127.0.0.1:5000/search
  Payload: ' OR '1'='1

[2] Buscando vulnerabilidades de XSS...
  [VULNERABLE] XSS Reflejado detectado en http://127.0.0.1:5000/comment
  Payload: <img src=x onerror="alert('XSS')">

[3] Buscando Information Disclosure...
  [VULNERABLE] Info sensible detectada: secret

[4] Buscando Weak Authentication...
  [VULNERABLE] Credencial débil: admin:password123

[5] Verificando Security Headers...
  [VULNERABLE] Headers de seguridad faltantes:
    - X-Content-Type-Options
    - X-Frame-Options

======================================================================
REPORTE DE ESCANEO - 2024-10-01 19:12:00
======================================================================

Total de vulnerabilidades encontradas: 5
  - CRITICAL: 2
  - HIGH: 1
  - MEDIUM: 1
  - LOW: 1
```

## Conceptos Clave para Explicar

### w3af vs Herramientas Modernas

| Aspecto | w3af | Burp Suite | OWASP ZAP |
|---------|------|-----------|-----------|
| Licencia | Gratis/GPLv2 | Gratis/Pago | Gratis |
| Mantenimiento | Limitado desde 2020 | Activo | Activo |
| Python 3 | w4af fork | No aplica | No aplica |
| Curva aprendizaje | Media | Alta | Media |
| Para educación | Bueno | Excelente | Excelente |

### Fases de Auditoría Web (como w3af lo haría)

1. **Reconocimiento/Crawling** - Mapear la aplicación
2. **Fingerprinting** - Identificar tecnologías
3. **Vulnerability Scanning** - Buscar vulnerabilidades
4. **Exploitation** - Verificar y explotar (cuando aplique)
5. **Reporting** - Documentar hallazgos

## Preguntas para Clase

1. ¿Qué otros payloads de SQL Injection conoces?
2. ¿Cómo se previene XSS?
3. ¿Qué información NUNCA debe exponerse?
4. ¿Por qué las contraseñas débiles son peligrosas?
5. ¿Para qué sirven los security headers?

## Recursos Adicionales

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- w3af Documentación: https://docs.w3af.org/
- Burp Suite Community: https://portswigger.net/burp/community
- OWASP ZAP: https://www.zaproxy.org/

## Notas Importantes

- Este código es SOLO para educación y demostración
- No usar en servidores de producción
- Siempre obtener permiso antes de testing de seguridad
- Reportar vulnerabilidades responsablemente

---

**Creado para demostración educativa de w3af**
