"""
Laboratorio MFA - Flask + PyOTP
Actividad 3 de Ciberseguridad.

Factor 1: usuario + contrasena.
Factor 2: codigo TOTP de seis digitos (Google Authenticator u otra app).

Las claves (FLASK_SECRET y TOTP_SECRET) se leen de variables de entorno.
Si no estan definidas, se generan unas de demostracion al arrancar (OJO: en ese
caso cambian en cada reinicio, por lo que el autenticador registrado dejara de
coincidir). En produccion deben guardarse de forma persistente y fuera del codigo.
"""

import os
from functools import wraps

import pyotp
from flask import (
    Flask, request, session, redirect, url_for, render_template, flash
)

app = Flask(__name__)

# ----------------------------------------------------------------------
# Configuracion y secretos (preferir variables de entorno)
# ----------------------------------------------------------------------
app.secret_key = os.environ.get("FLASK_SECRET") or os.urandom(24).hex()

# Credenciales FICTICIAS de demostracion. Nunca usar credenciales fijas en produccion.
DEMO_USER = os.environ.get("DEMO_USER", "demo")
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "demo1234")

# Clave TOTP en Base32. Si no se define, se genera una (cambia en cada reinicio).
TOTP_SECRET = os.environ.get("TOTP_SECRET") or pyotp.random_base32()

# Datos para mostrar en el autenticador
ISSUER = "ActividadMFA"
ACCOUNT = DEMO_USER


# ----------------------------------------------------------------------
# Decorador: protege rutas hasta completar el segundo factor
# ----------------------------------------------------------------------
def requires_mfa(view):
    @wraps(view)  # conserva nombre y metadatos de la funcion original
    def wrapper(*args, **kwargs):
        if not session.get("mfa_ok"):
            flash("Debes completar la autenticacion en dos factores.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


# ----------------------------------------------------------------------
# Rutas
# ----------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    """Primer factor: usuario + contrasena."""
    if request.method == "POST":
        session.clear()  # limpia cualquier sesion anterior
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_USER and password == DEMO_PASSWORD:
            session["factor1"] = True
            return redirect(url_for("verify"))
        # Mensaje generico: no revela cual dato fallo
        return render_template("login.html", error="Usuario o contrasena invalidos")
    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    """Segundo factor: codigo TOTP."""
    if not session.get("factor1"):  # no se puede verificar sin el primer factor
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not (code.isdigit() and len(code) == 6):
            return render_template("verify.html", error="El codigo debe tener 6 digitos")
        # valid_window=1 tolera un pequeno desfase de reloj
        if pyotp.TOTP(TOTP_SECRET).verify(code, valid_window=1):
            session["mfa_ok"] = True
            return redirect(url_for("dashboard"))
        return render_template("verify.html", error="Codigo incorrecto o vencido")
    return render_template("verify.html")


@app.route("/setup")
def setup():
    """Muestra los datos para registrar el autenticador. Requiere el primer factor."""
    if not session.get("factor1"):
        return redirect(url_for("login"))
    uri = pyotp.TOTP(TOTP_SECRET).provisioning_uri(name=ACCOUNT, issuer_name=ISSUER)

    # QR opcional: si 'qrcode' esta instalado, se genera una imagen embebida.
    qr_data_uri = None
    try:
        import io
        import base64
        import qrcode
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_data_uri = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        qr_data_uri = None  # sin QR: se usa la clave manual

    return render_template(
        "setup.html", secret=TOTP_SECRET, uri=uri, qr=qr_data_uri
    )


@app.route("/dashboard")
@requires_mfa
def dashboard():
    """Area protegida: solo accesible tras MFA completo."""
    return render_template("dashboard.html", user=DEMO_USER)


@app.route("/logout", methods=["POST"])
def logout():
    """Cierra la sesion y elimina los indicadores de autenticacion."""
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # Puerto 5001 para evitar conflictos con otras practicas (LocalStack usa 4566).
    app.run(host="127.0.0.1", port=5001, debug=True)
