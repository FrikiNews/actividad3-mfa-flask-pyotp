# Laboratorio MFA con Flask + PyOTP

Práctica B de la Actividad 3 de Ciberseguridad. Implementa autenticación en dos factores
(MFA) y comprueba que la contraseña por sí sola no da acceso al área protegida.

- **Factor 1:** usuario + contraseña.
- **Factor 2:** código TOTP de 6 dígitos (Google Authenticator u otra app).

## Requisitos

- Python 3.10+
- Una app TOTP (Google Authenticator, Authy, etc.)

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configuración (secretos)

Define los secretos por variable de entorno (recomendado):

```bash
cp .env.example .env             # edita .env
export $(grep -v '^#' .env | xargs)   # Linux/macOS
```

Si no defines `TOTP_SECRET`, la app genera una clave al arrancar, pero **cambia en cada
reinicio**, así que el autenticador registrado dejará de coincidir. Por eso en producción
la clave debe guardarse de forma persistente.

## Ejecutar

```bash
python -m py_compile app.py      # revisa sintaxis
python app.py                    # arranca en http://127.0.0.1:5001
```

## Recorrido

1. Entra a `http://127.0.0.1:5001/` e inicia sesión (`demo` / `demo1234`).
2. Ve a **Configurar** (`/setup`) y escanea el QR con tu app TOTP.
3. En `/verify` escribe el código de 6 dígitos.
4. Entras a `/dashboard` (protegido). Cierra sesión y verifica que no puedes volver.

## Pruebas funcionales

| Prueba | Resultado esperado |
| --- | --- |
| Usuario o contraseña incorrectos | Denegar acceso |
| Contraseña correcta | Pedir el segundo factor |
| Código TOTP inválido | Mantener bloqueado |
| Código TOTP vigente | Entrar al dashboard |
| Abrir `/dashboard` sin sesión | Redirigir al login |
| Cerrar sesión y volver al dashboard | Impedir el regreso |

## Seguridad

- Los secretos (`FLASK_SECRET`, `TOTP_SECRET`) van en variables de entorno, no en el código.
- Las credenciales de demostración no deben usarse en producción.
- El decorador `requires_mfa` bloquea el área protegida hasta validar los dos factores.
- Mejoras recomendadas: límite de intentos, rechazo de códigos reutilizados y persistencia segura de la clave.
