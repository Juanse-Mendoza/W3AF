#!/usr/bin/env python3
"""
Script de Auditoría Web - Simula funcionalidad de w3af
Demuestra cómo se detectan vulnerabilidades comunes
"""

import requests
import re
import os
import webbrowser
import http.server
import socketserver
import functools
from urllib.parse import urljoin, urlparse
import sys
from typing import List, Dict
from datetime import datetime

# Puerto por defecto donde se sirve el reporte HTML (se prueban los siguientes
# 10 puertos si este está ocupado)
REPORT_PORT = 8090

# Remediación recomendada por tipo de vulnerabilidad (se usa en el reporte HTML)
REMEDIACIONES = {
    'SQL Injection': "Usar consultas parametrizadas (prepared statements) en vez de "
                      "concatenar strings. Ej: cursor.execute('SELECT * FROM users WHERE name = ?', (username,))",
    'Cross-Site Scripting (XSS)': "Sanitizar/escapar toda salida que incluya datos del usuario "
                      "(ej. markupsafe.escape en Flask) y aplicar una Content-Security-Policy.",
    'Information Disclosure': "Eliminar endpoints de debug en producción, no exponer secretos, "
                      "paths del servidor ni versiones de software en las respuestas.",
    'Weak Authentication': "Exigir contraseñas fuertes, almacenar hashes con bcrypt/argon2, "
                      "aplicar rate limiting en login y habilitar autenticación multi-factor (MFA).",
    'Missing Security Headers': "Configurar headers de seguridad (X-Frame-Options, "
                      "X-Content-Type-Options, Content-Security-Policy, HSTS) en cada respuesta.",
}

# Fases de auditoría que este scanner ejecuta (mismo flujo conceptual que w3af)
FASES_METODOLOGIA = [
    ("Reconocimiento", "Se define el objetivo (base_url) y se abre una sesión HTTP persistente."),
    ("Inyección de payloads", "Se envían payloads de prueba conocidos (SQLi, XSS) a los endpoints "
                               "y credenciales comunes al login."),
    ("Análisis de respuesta", "Se inspecciona el contenido, código de estado y headers de cada "
                               "respuesta buscando indicadores de vulnerabilidad."),
    ("Clasificación", "Cada hallazgo se etiqueta con un tipo y severidad (CRITICAL/HIGH/MEDIUM/LOW)."),
    ("Reporte", "Se genera un resumen consolidado en terminal y en HTML con evidencia y remediación."),
]

class WebAuditScanner:
    """Scanner educativo que simula w3af"""

    def __init__(self, base_url: str, verbose: bool = True):
        self.base_url = base_url
        self.verbose = verbose
        self.session = requests.Session()
        self.vulnerabilities = []
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def log(self, message: str, level: str = "INFO"):
        """Imprime logs formateados"""
        if self.verbose:
            print(f"[{level}] {message}")

    def start_scan(self):
        """Inicia el escaneo"""
        self.log("="*70)
        self.log(f"INICIANDO ESCANEO WEB - {self.timestamp}", "SCANNER")
        self.log(f"Objetivo: {self.base_url}")
        self.log("="*70)

        try:
            self.scan_sql_injection()
            self.scan_xss()
            self.scan_information_disclosure()
            self.scan_weak_authentication()
            self.scan_security_headers()
            self.generate_report()
            self.generate_html_report()
        except Exception as e:
            self.log(f"Error durante escaneo: {str(e)}", "ERROR")

    def scan_sql_injection(self):
        """Prueba SQL Injection"""
        self.log("\n[1] Buscando vulnerabilidades de SQL Injection...", "SCAN")

        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' --",
            "' UNION SELECT NULL--"
        ]

        endpoint = f"{self.base_url}/search"

        for payload in sql_payloads:
            try:
                params = {'q': payload}
                response = self.session.get(endpoint, params=params, timeout=5)

                # Indicadores de SQL Injection
                indicators = [
                    'sqlite3.OperationalError',
                    'SQL syntax',
                    'database error',
                    'Error:',
                    'unrecognized token'
                ]

                if any(indicator in response.text for indicator in indicators):
                    vuln = {
                        'type': 'SQL Injection',
                        'endpoint': endpoint,
                        'payload': payload,
                        'severity': 'CRITICAL',
                        'description': 'La aplicación es vulnerable a SQL Injection'
                    }
                    self.vulnerabilities.append(vuln)
                    self.log(f"  [VULNERABLE] SQL Injection detectada en {endpoint}", "CRITICAL")
                    self.log(f"  Payload: {payload}")
                    return

            except Exception as e:
                self.log(f"  Error probando {endpoint}: {str(e)}", "WARNING")

        self.log("  [INFO] No se detectó SQL Injection", "INFO")

    def scan_xss(self):
        """Prueba Cross-Site Scripting (XSS)"""
        self.log("\n[2] Buscando vulnerabilidades de XSS...", "SCAN")

        xss_payloads = [
            '<img src=x onerror="alert(\'XSS\')">',
            '<script>alert("XSS")</script>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '<svg onload=alert("XSS")>'
        ]

        endpoint = f"{self.base_url}/comment"

        for payload in xss_payloads:
            try:
                params = {'msg': payload}
                response = self.session.get(endpoint, params=params, timeout=5)

                # Verifica si el payload se refleja sin sanitizar
                if payload in response.text:
                    vuln = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'endpoint': endpoint,
                        'payload': payload,
                        'severity': 'HIGH',
                        'description': 'La aplicación es vulnerable a XSS'
                    }
                    self.vulnerabilities.append(vuln)
                    self.log(f"  [VULNERABLE] XSS Reflejado detectado en {endpoint}", "HIGH")
                    self.log(f"  Payload: {payload}")
                    return

            except Exception as e:
                self.log(f"  Error probando {endpoint}: {str(e)}", "WARNING")

        self.log("  [INFO] No se detectó XSS", "INFO")

    def scan_information_disclosure(self):
        """Busca exposición de información sensible"""
        self.log("\n[3] Buscando Information Disclosure...", "SCAN")

        sensitive_endpoints = [
            '/debug',
            '/admin',
            '/config',
            '/.env',
            '/secret'
        ]

        sensitive_keywords = [
            'password',
            'secret',
            'api_key',
            'token',
            'admin',
            'database',
            'server_path'
        ]

        for endpoint in sensitive_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=5)

                if response.status_code == 200:
                    # Busca palabras clave sensibles
                    for keyword in sensitive_keywords:
                        if keyword.lower() in response.text.lower():
                            vuln = {
                                'type': 'Information Disclosure',
                                'endpoint': url,
                                'severity': 'MEDIUM',
                                'description': f'Información sensible expuesta ({keyword})',
                                'keyword': keyword
                            }
                            self.vulnerabilities.append(vuln)
                            self.log(f"  [VULNERABLE] Info sensible detectada: {keyword}", "MEDIUM")
                            return

            except Exception as e:
                pass

        self.log("  [INFO] No se detectó Information Disclosure evidente", "INFO")

    def scan_weak_authentication(self):
        """Prueba credenciales débiles"""
        self.log("\n[4] Buscando Weak Authentication...", "SCAN")

        weak_credentials = [
            ('admin', 'password123'),
            ('admin', 'admin'),
            ('user1', 'user1234'),
            ('test', 'test'),
            ('admin', '123456')
        ]

        endpoint = f"{self.base_url}/login"

        for username, password in weak_credentials:
            try:
                params = {'user': username, 'pass': password}
                response = self.session.get(endpoint, params=params, timeout=5)

                if 'Bienvenido' in response.text or 'Welcome' in response.text:
                    vuln = {
                        'type': 'Weak Authentication',
                        'endpoint': endpoint,
                        'credentials': f'{username}:{password}',
                        'severity': 'CRITICAL',
                        'description': 'Se detectaron credenciales débiles'
                    }
                    self.vulnerabilities.append(vuln)
                    self.log(f"  [VULNERABLE] Credencial débil: {username}:{password}", "CRITICAL")
                    return

            except Exception as e:
                self.log(f"  Error probando {endpoint}: {str(e)}", "WARNING")

        self.log("  [INFO] No se detectaron credenciales débiles", "INFO")

    def scan_security_headers(self):
        """Verifica headers de seguridad"""
        self.log("\n[5] Verificando Security Headers...", "SCAN")

        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]

        try:
            response = self.session.get(self.base_url, timeout=5)

            missing_headers = []
            for header in required_headers:
                if header not in response.headers:
                    missing_headers.append(header)

            if missing_headers:
                vuln = {
                    'type': 'Missing Security Headers',
                    'endpoint': self.base_url,
                    'severity': 'LOW',
                    'description': f'Faltan headers de seguridad: {", ".join(missing_headers)}',
                    'missing': missing_headers
                }
                self.vulnerabilities.append(vuln)
                self.log(f"  [VULNERABLE] Headers de seguridad faltantes:", "LOW")
                for header in missing_headers:
                    self.log(f"    - {header}")

        except Exception as e:
            self.log(f"  Error verificando headers: {str(e)}", "WARNING")

    def generate_report(self):
        """Genera reporte final"""
        self.log("\n" + "="*70)
        self.log(f"REPORTE DE ESCANEO - {self.timestamp}", "REPORT")
        self.log("="*70)

        # Resumen
        total_vulns = len(self.vulnerabilities)
        critical = sum(1 for v in self.vulnerabilities if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in self.vulnerabilities if v.get('severity') == 'HIGH')
        medium = sum(1 for v in self.vulnerabilities if v.get('severity') == 'MEDIUM')
        low = sum(1 for v in self.vulnerabilities if v.get('severity') == 'LOW')

        self.log(f"\nTotal de vulnerabilidades encontradas: {total_vulns}")
        self.log(f"  - CRITICAL: {critical}")
        self.log(f"  - HIGH: {high}")
        self.log(f"  - MEDIUM: {medium}")
        self.log(f"  - LOW: {low}")

        # Detalles
        if self.vulnerabilities:
            self.log("\nVulnerabilidades Detectadas:", "DETAILS")
            self.log("-" * 70)

            for i, vuln in enumerate(self.vulnerabilities, 1):
                self.log(f"\n[{i}] {vuln['type']}")
                self.log(f"    Severidad: {vuln.get('severity', 'N/A')}")
                self.log(f"    Endpoint: {vuln.get('endpoint', 'N/A')}")
                self.log(f"    Descripción: {vuln.get('description', 'N/A')}")

                if 'payload' in vuln:
                    self.log(f"    Payload: {vuln['payload']}")
                if 'credentials' in vuln:
                    self.log(f"    Credenciales: {vuln['credentials']}")

        self.log("\n" + "="*70)
        self.log("FIN DEL ESCANEO", "REPORT")
        self.log("="*70)

    def generate_html_report(self, output_file: str = "reporte_auditoria.html", auto_open: bool = True,
                              port: int = REPORT_PORT):
        """Genera un reporte visual en HTML con lo que hizo el scanner y cómo lo hizo"""
        total_vulns = len(self.vulnerabilities)
        counts = {
            'CRITICAL': sum(1 for v in self.vulnerabilities if v.get('severity') == 'CRITICAL'),
            'HIGH': sum(1 for v in self.vulnerabilities if v.get('severity') == 'HIGH'),
            'MEDIUM': sum(1 for v in self.vulnerabilities if v.get('severity') == 'MEDIUM'),
            'LOW': sum(1 for v in self.vulnerabilities if v.get('severity') == 'LOW'),
        }

        severity_colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#ea580c',
            'MEDIUM': '#d97706',
            'LOW': '#2563eb',
        }

        # Tarjetas de resumen por severidad
        summary_cards = "".join(
            f"""<div class="card" style="border-top:4px solid {severity_colors[sev]}">
                    <div class="card-count" style="color:{severity_colors[sev]}">{counts[sev]}</div>
                    <div class="card-label">{sev}</div>
                </div>"""
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        )

        # Pasos de metodología
        steps_html = "".join(
            f"""<li><strong>{nombre}</strong> &mdash; {desc}</li>"""
            for nombre, desc in FASES_METODOLOGIA
        )

        # Tarjetas de hallazgos
        if self.vulnerabilities:
            findings_html = ""
            for i, vuln in enumerate(self.vulnerabilities, 1):
                sev = vuln.get('severity', 'LOW')
                color = severity_colors.get(sev, '#6b7280')
                remediacion = REMEDIACIONES.get(vuln['type'], "Revisar y corregir según buenas prácticas OWASP.")

                extra_rows = ""
                if 'payload' in vuln:
                    extra_rows += f"<tr><td>Payload usado</td><td><code>{self._escape(vuln['payload'])}</code></td></tr>"
                if 'credentials' in vuln:
                    extra_rows += f"<tr><td>Credenciales probadas</td><td><code>{self._escape(vuln['credentials'])}</code></td></tr>"
                if 'keyword' in vuln:
                    extra_rows += f"<tr><td>Palabra clave detectada</td><td><code>{self._escape(vuln['keyword'])}</code></td></tr>"
                if 'missing' in vuln:
                    extra_rows += f"<tr><td>Headers faltantes</td><td><code>{self._escape(', '.join(vuln['missing']))}</code></td></tr>"

                findings_html += f"""
                <div class="finding">
                    <div class="finding-header" style="background:{color}">
                        <span class="badge">{sev}</span>
                        <span class="finding-title">#{i} &middot; {self._escape(vuln['type'])}</span>
                    </div>
                    <table class="finding-table">
                        <tr><td>Endpoint</td><td><code>{self._escape(vuln.get('endpoint', 'N/A'))}</code></td></tr>
                        <tr><td>Descripción</td><td>{self._escape(vuln.get('description', 'N/A'))}</td></tr>
                        {extra_rows}
                        <tr><td>Remediación</td><td class="remediation">{self._escape(remediacion)}</td></tr>
                    </table>
                </div>"""
        else:
            findings_html = '<p class="no-findings">No se detectaron vulnerabilidades en este escaneo.</p>'

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Reporte de Auditoría Web</title>
<style>
    body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#f3f4f6; color:#111827; margin:0; padding:0 0 60px; }}
    header {{ background:#111827; color:white; padding:32px 24px; }}
    header h1 {{ margin:0 0 6px; font-size:26px; }}
    header p {{ margin:2px 0; color:#9ca3af; font-size:14px; }}
    main {{ max-width:900px; margin:0 auto; padding:24px; }}
    section {{ background:white; border-radius:10px; padding:24px; margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,0.08); }}
    section h2 {{ margin-top:0; font-size:18px; border-bottom:1px solid #e5e7eb; padding-bottom:10px; }}
    .cards {{ display:flex; gap:16px; flex-wrap:wrap; }}
    .card {{ flex:1; min-width:110px; background:#f9fafb; border-radius:8px; padding:16px; text-align:center; }}
    .card-count {{ font-size:32px; font-weight:bold; }}
    .card-label {{ font-size:12px; color:#6b7280; letter-spacing:0.05em; }}
    ol {{ padding-left:20px; }}
    ol li {{ margin-bottom:10px; line-height:1.5; }}
    .finding {{ border:1px solid #e5e7eb; border-radius:8px; margin-bottom:16px; overflow:hidden; }}
    .finding-header {{ color:white; padding:10px 16px; display:flex; gap:10px; align-items:center; }}
    .badge {{ background:rgba(255,255,255,0.25); padding:2px 8px; border-radius:4px; font-size:12px; font-weight:bold; }}
    .finding-title {{ font-weight:600; }}
    .finding-table {{ width:100%; border-collapse:collapse; }}
    .finding-table td {{ padding:10px 16px; border-bottom:1px solid #f3f4f6; vertical-align:top; font-size:14px; }}
    .finding-table td:first-child {{ width:180px; color:#6b7280; font-weight:600; }}
    .remediation {{ color:#065f46; background:#ecfdf5; }}
    code {{ background:#f3f4f6; padding:2px 6px; border-radius:4px; font-size:13px; }}
    .no-findings {{ color:#059669; font-weight:600; }}
    footer {{ text-align:center; color:#9ca3af; font-size:12px; margin-top:24px; }}
</style>
</head>
<body>
<header>
    <h1>Reporte de Auditoría Web</h1>
    <p>Objetivo escaneado: {self._escape(self.base_url)}</p>
    <p>Fecha del escaneo: {self.timestamp}</p>
</header>
<main>
    <section>
        <h2>Resumen Ejecutivo</h2>
        <div class="cards">{summary_cards}</div>
        <p style="margin-top:16px; color:#4b5563;">Total de vulnerabilidades encontradas: <strong>{total_vulns}</strong></p>
    </section>

    <section>
        <h2>¿Qué hizo el scanner y cómo? (Metodología)</h2>
        <ol>{steps_html}</ol>
    </section>

    <section>
        <h2>Hallazgos Detallados</h2>
        {findings_html}
    </section>
</main>
<footer>Generado automáticamente por web_audit_scanner.py &mdash; Demo educativa, no usar en producción.</footer>
</body>
</html>"""

        output_path = os.path.abspath(output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        self.log(f"\nReporte HTML generado en: {output_path}", "REPORT")

        if auto_open:
            self._serve_html_report(output_path, port=port)

    def _serve_html_report(self, output_path: str, port: int = REPORT_PORT):
        """Levanta un servidor HTTP local y abre el reporte en el navegador por ese puerto.

        Se prueban hasta 10 puertos a partir de `port` por si el primero está ocupado.
        El servidor queda corriendo hasta que se presione Ctrl+C.
        """
        directory = os.path.dirname(output_path) or '.'
        filename = os.path.basename(output_path)
        handler_class = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)

        httpd = None
        used_port = None
        for candidate_port in range(port, port + 10):
            try:
                # 0.0.0.0 para que Codespaces/Docker puedan exponer el puerto;
                # sigue siendo accesible por 127.0.0.1 en tu máquina local.
                httpd = socketserver.TCPServer(("0.0.0.0", candidate_port), handler_class)
                used_port = candidate_port
                break
            except OSError:
                continue  # puerto ocupado, probar el siguiente

        if httpd is None:
            self.log(f"No se pudo abrir ningún puerto libre entre {port} y {port + 9} para el reporte", "WARNING")
            return

        # Si corre dentro de un GitHub Codespace, armamos la URL pública que
        # GitHub expone para ese puerto en vez de localhost
        codespace_name = os.environ.get('CODESPACE_NAME')
        forwarding_domain = os.environ.get('GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN', 'app.github.dev')

        if codespace_name:
            url = f"https://{codespace_name}-{used_port}.{forwarding_domain}/{filename}"
            self.log(f"Reporte disponible en: {url}", "REPORT")
            self.log("(Ejecutando en GitHub Codespaces: abre la pestaña 'Ports' y marca el", "REPORT")
            self.log(f" puerto {used_port} como público, o haz click en el link del tab 'Ports')", "REPORT")
        else:
            url = f"http://127.0.0.1:{used_port}/{filename}"
            self.log(f"Reporte disponible en: {url}", "REPORT")

        self.log("Presiona Ctrl+C en esta terminal para detener el servidor del reporte.", "REPORT")

        if not codespace_name:
            # En un contenedor remoto como Codespaces no hay navegador local que abrir
            try:
                webbrowser.open(url)
            except Exception:
                pass

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            self.log("\nDeteniendo servidor del reporte...", "INFO")
        finally:
            httpd.server_close()

    @staticmethod
    def _escape(text) -> str:
        """Escapa HTML para que el reporte no sea vulnerable a lo mismo que detecta"""
        text = str(text)
        return (text.replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('"', '&quot;')
                    .replace("'", '&#39;'))

def main():
    """Función principal"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://127.0.0.1:5000"

    scanner = WebAuditScanner(base_url)
    scanner.start_scan()

if __name__ == '__main__':
    main()
