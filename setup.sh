#!/bin/bash
# Setup y ejecución de la demostración de w3af

echo "=========================================="
echo "DEMO w3af - Setup Automático"
echo "=========================================="
echo ""

# Verificar Python
echo "[1] Verificando Python..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 no encontrado"
    exit 1
fi
python_version=$(python3 --version)
echo "    OK: $python_version"
echo ""

# Instalar dependencias
echo "[2] Instalando dependencias..."
pip install -q flask requests
echo "    OK: Flask y requests instalados"
echo ""

# Información de archivos
echo "[3] Archivos disponibles:"
echo ""
echo "    vulnerable_app.py"
echo "    - Aplicación web con vulnerabilidades"
echo "    - Ejecutar: python vulnerable_app.py"
echo ""
echo "    web_audit_scanner.py"
echo "    - Scanner que detecta vulnerabilidades"
echo "    - Ejecutar: python web_audit_scanner.py"
echo ""
echo "    ejemplos_vulnerabilidades.py"
echo "    - Ejemplos de código vulnerable"
echo "    - Ejecutar: python ejemplos_vulnerabilidades.py"
echo ""
echo "    README.md"
echo "    - Guía completa de la demostración"
echo ""

# Instrucciones
echo "=========================================="
echo "INSTRUCCIONES DE USO"
echo "=========================================="
echo ""
echo "OPCIÓN 1: Demostración Completa (Recomendado)"
echo "  1. Terminal 1: python vulnerable_app.py"
echo "  2. Terminal 2: python web_audit_scanner.py"
echo "  3. Navegador: http://127.0.0.1:5000"
echo ""
echo "OPCIÓN 2: Solo Ejemplos (Sin servidor)"
echo "  1. Terminal: python ejemplos_vulnerabilidades.py"
echo ""
echo "OPCIÓN 3: Ver documentación"
echo "  1. cat README.md"
echo ""
echo "=========================================="
echo ""
