# Permite usar anotaciones de tipos modernas aunque se ejecute en versiones anteriores de Python.
# Es una buena práctica cuando se quiere escribir código más limpio y mantenible.
from __future__ import annotations

# Módulos estándar de Python.
import os              # Permite leer variables de entorno del sistema.
import re              # Permite usar expresiones regulares para validar textos.
import secrets         # Permite generar tokens seguros, por ejemplo para CSRF.
import sqlite3         # Librería integrada para trabajar con bases de datos SQLite.
from datetime import datetime, timedelta, timezone  # Fechas y tiempos con zona horaria.
from functools import wraps                         # Mantiene metadatos al crear decoradores.
from pathlib import Path                            # Manejo moderno de rutas de archivos.
from typing import Any, Callable                    # Tipado para funciones y decoradores.

# Importaciones principales de Flask.
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# Funciones de Werkzeug para trabajar con contraseñas de forma segura.
from werkzeug.security import check_password_hash, generate_password_hash


# ============================================================================
# CONFIGURACIÓN GENERAL
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "data" / "database.db"))
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,30}$")

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10

MAX_TITLE_LENGTH = 100
MAX_DESCRIPTION_LENGTH = 500


# ============================================================================
# FACTORÍA DE APLICACIÓN FLASK
# ============================================================================

def create_app() -> Flask:
    """
    Crea y configura la aplicación Flask.
    """

    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=SECRET_KEY,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=1024 * 1024,
    )

    @app.before_request
    def before_request() -> None:
        """
        Se ejecuta antes de cada petición HTTP.
        """

        ensure_database_directory()
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        init_db(g.db)

    @app.after_request
    def add_security_headers(response):
        """
        Se ejecuta después de cada petición HTTP.
        """

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )

        return response

    @app.teardown_request
    def teardown_request(exception=None) -> None:
        """
        Se ejecuta al terminar cada petición.
        """

        db = getattr(g, "db", None)

        if db is not None:
            db.close()

    @app.context_processor
    def inject_security_helpers():
        """
        Hace que csrf_token() esté disponible dentro de las plantillas HTML.
        """

        return {"csrf_token": generate_csrf_token}

    def login_required(view: Callable[..., Any]):
        """
        Decorador para proteger rutas.
        """

        @wraps(view)
        def wrapped_view(**kwargs):
            if "user_id" not in session:
                flash("Debes iniciar sesión para acceder.")
                return redirect(url_for("login"))

            return view(**kwargs)

        return wrapped_view

    @app.route("/")
    def index():
        """
        Ruta raíz.
        """

        if "user_id" in session:
            return redirect(url_for("tasks"))

        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """
        Permite crear una cuenta nueva.

        GET: muestra formulario.
        POST: procesa formulario.
        """

        if "user_id" in session:
            return redirect(url_for("tasks"))

        if request.method == "POST":
            if not validate_csrf_token():
                flash("Solicitud no válida. Inténtalo de nuevo.")
                return render_template("register.html"), 400

            # Se leen datos del formulario.
            username = normalize_text(request.form.get("username", ""))
            password = request.form.get("password", "")

            # Se lee la confirmación de contraseña.
            # Este campo permite comprobar que el usuario no se ha equivocado al escribirla.
            confirm_password = request.form.get("confirm_password", "")

            # Validación de usuario, contraseña y confirmación de contraseña.
            validation_error = validate_registration(username, password, confirm_password)

            if validation_error:
                flash(validation_error)
                log_security_event("REGISTER_VALIDATION_FAILED", username)
                return render_template("register.html")

            password_hash = generate_password_hash(
                password,
                method="pbkdf2:sha256:600000",
                salt_length=16,
            )

            try:
                g.db.execute(
                    """
                    INSERT INTO users (username, password_hash)
                    VALUES (?, ?)
                    """,
                    (username, password_hash),
                )
                g.db.commit()

                log_security_event("USER_REGISTERED", username)

            except sqlite3.IntegrityError:
                flash("El usuario ya existe.")
                log_security_event("REGISTER_DUPLICATED_USER", username)
                return render_template("register.html")

            flash("Usuario registrado correctamente. Inicia sesión.")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """
        Permite iniciar sesión.
        """

        if "user_id" in session:
            return redirect(url_for("tasks"))

        if request.method == "POST":
            if not validate_csrf_token():
                flash("Solicitud no válida. Inténtalo de nuevo.")
                return render_template("login.html"), 400

            username = normalize_text(request.form.get("username", ""))
            password = request.form.get("password", "")

            client_ip = get_client_ip()

            if is_user_locked(username, client_ip):
                flash("Demasiados intentos fallidos. Inténtalo más tarde.")
                log_security_event("LOGIN_LOCKED", username)
                return render_template("login.html"), 429

            user = g.db.execute(
                """
                SELECT id, username, password_hash
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

            if user is None or not check_password_hash(user["password_hash"], password):
                register_failed_login(username, client_ip)
                log_security_event("LOGIN_FAILED", username)
                flash("Credenciales incorrectas.")
                return render_template("login.html")

            clear_failed_logins(username, client_ip)

            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            log_security_event("LOGIN_SUCCESS", user["username"])

            flash("Sesión iniciada correctamente.")
            return redirect(url_for("tasks"))

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        """
        Cierra sesión.
        """

        if not validate_csrf_token():
            flash("Solicitud no válida. Inténtalo de nuevo.")
            return redirect(url_for("index"))

        username = session.get("username", "anonymous")
        session.clear()

        log_security_event("LOGOUT", username)

        flash("Sesión cerrada correctamente.")
        return redirect(url_for("login"))

    @app.route("/tasks", methods=["GET", "POST"])
    @login_required
    def tasks():
        """
        GET: muestra las tareas del usuario autenticado.
        POST: crea una nueva tarea.
        """

        if request.method == "POST":
            if not validate_csrf_token():
                flash("Solicitud no válida. Inténtalo de nuevo.")
                return redirect(url_for("tasks"))

            title = normalize_text(request.form.get("title", ""))
            description = normalize_text(request.form.get("description", ""))

            validation_error = validate_task(title, description)

            if validation_error:
                flash(validation_error)
                log_security_event("TASK_VALIDATION_FAILED", session["username"])
                return redirect(url_for("tasks"))

            g.db.execute(
                """
                INSERT INTO tasks (user_id, title, description)
                VALUES (?, ?, ?)
                """,
                (session["user_id"], title, description),
            )
            g.db.commit()

            log_security_event("TASK_CREATED", session["username"])

            flash("Tarea creada correctamente.")
            return redirect(url_for("tasks"))

        user_tasks = g.db.execute(
            """
            SELECT id, title, description, done, created_at
            FROM tasks
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (session["user_id"],),
        ).fetchall()

        return render_template("tasks.html", tasks=user_tasks)

    @app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
    @login_required
    def toggle_task(task_id: int):
        """
        Cambia el estado de una tarea.
        """

        if not validate_csrf_token():
            flash("Solicitud no válida. Inténtalo de nuevo.")
            return redirect(url_for("tasks"))

        task = get_user_task(task_id)

        if task is None:
            flash("Tarea no encontrada.")
            log_security_event("TASK_TOGGLE_NOT_FOUND", session["username"])
            return redirect(url_for("tasks"))

        new_status = 0 if task["done"] else 1

        g.db.execute(
            """
            UPDATE tasks
            SET done = ?
            WHERE id = ? AND user_id = ?
            """,
            (new_status, task_id, session["user_id"]),
        )
        g.db.commit()

        log_security_event("TASK_STATUS_UPDATED", session["username"])

        flash("Estado de la tarea actualizado.")
        return redirect(url_for("tasks"))

    @app.route("/tasks/<int:task_id>/delete", methods=["POST"])
    @login_required
    def delete_task(task_id: int):
        """
        Elimina una tarea del usuario autenticado.
        """

        if not validate_csrf_token():
            flash("Solicitud no válida. Inténtalo de nuevo.")
            return redirect(url_for("tasks"))

        task = get_user_task(task_id)

        if task is None:
            flash("Tarea no encontrada.")
            log_security_event("TASK_DELETE_NOT_FOUND", session["username"])
            return redirect(url_for("tasks"))

        g.db.execute(
            """
            DELETE FROM tasks
            WHERE id = ? AND user_id = ?
            """,
            (task_id, session["user_id"]),
        )
        g.db.commit()

        log_security_event("TASK_DELETED", session["username"])

        flash("Tarea eliminada correctamente.")
        return redirect(url_for("tasks"))

    @app.errorhandler(404)
    def not_found(error):
        return render_template(
            "error.html",
            title="Página no encontrada",
            message="El recurso solicitado no existe.",
        ), 404

    @app.errorhandler(413)
    def payload_too_large(error):
        return render_template(
            "error.html",
            title="Solicitud demasiado grande",
            message="El contenido enviado supera el tamaño máximo permitido.",
        ), 413

    @app.errorhandler(500)
    def internal_error(error):
        return render_template(
            "error.html",
            title="Error interno",
            message="Ha ocurrido un error inesperado.",
        ), 500

    return app


# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

def ensure_database_directory() -> None:
    database_file = Path(DATABASE_PATH)
    database_file.parent.mkdir(parents=True, exist_ok=True)


def normalize_text(value: str) -> str:
    return value.strip()


def generate_csrf_token() -> str:
    token = session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token

    return token


def validate_csrf_token() -> bool:
    form_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")

    return bool(
        form_token
        and session_token
        and secrets.compare_digest(form_token, session_token)
    )


def validate_registration(username: str, password: str, confirm_password: str) -> str | None:
    """
    Valida los datos de registro.

    Devuelve:
    - None si todo es correcto
    - un mensaje de error si algo falla
    """

    if not USERNAME_PATTERN.match(username):
        return "El usuario debe tener entre 3 y 30 caracteres y solo puede contener letras, números, guiones, puntos o guiones bajos."

    if len(password) < 8:
        return "La contraseña debe tener al menos 8 caracteres."

    if password != confirm_password:
        return "Las contraseñas no coinciden."

    if len(password) > 128:
        return "La contraseña no puede superar los 128 caracteres."

    if not re.search(r"[A-Z]", password):
        return "La contraseña debe contener al menos una letra mayúscula."

    if not re.search(r"[a-z]", password):
        return "La contraseña debe contener al menos una letra minúscula."

    if not re.search(r"\d", password):
        return "La contraseña debe contener al menos un número."

    if not re.search(r"[^a-zA-Z0-9]", password):
        return "La contraseña debe contener al menos un carácter especial."

    return None


def validate_task(title: str, description: str) -> str | None:
    if not title:
        return "El título de la tarea es obligatorio."

    if len(title) > MAX_TITLE_LENGTH:
        return f"El título debe tener como máximo {MAX_TITLE_LENGTH} caracteres."

    if len(description) > MAX_DESCRIPTION_LENGTH:
        return f"La descripción debe tener como máximo {MAX_DESCRIPTION_LENGTH} caracteres."

    return None


def get_user_task(task_id: int):
    return g.db.execute(
        """
        SELECT id, done
        FROM tasks
        WHERE id = ? AND user_id = ?
        """,
        (task_id, session["user_id"]),
    ).fetchone()


def get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "unknown"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def register_failed_login(username: str, ip_address: str) -> None:
    g.db.execute(
        """
        INSERT INTO login_attempts (username, ip_address, attempted_at)
        VALUES (?, ?, ?)
        """,
        (username, ip_address, utc_now().isoformat()),
    )
    g.db.commit()


def clear_failed_logins(username: str, ip_address: str) -> None:
    g.db.execute(
        """
        DELETE FROM login_attempts
        WHERE username = ? OR ip_address = ?
        """,
        (username, ip_address),
    )
    g.db.commit()


def is_user_locked(username: str, ip_address: str) -> bool:
    threshold = utc_now() - timedelta(minutes=LOCKOUT_MINUTES)

    attempts = g.db.execute(
        """
        SELECT COUNT(*) AS total
        FROM login_attempts
        WHERE (username = ? OR ip_address = ?)
        AND attempted_at >= ?
        """,
        (username, ip_address, threshold.isoformat()),
    ).fetchone()

    return attempts["total"] >= MAX_LOGIN_ATTEMPTS


def log_security_event(event_type: str, username: str = "anonymous") -> None:
    g.db.execute(
        """
        INSERT INTO security_events (event_type, username, ip_address, user_agent, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            event_type,
            username,
            get_client_ip(),
            request.headers.get("User-Agent", "unknown")[:255],
            utc_now().isoformat(),
        ),
    )
    g.db.commit()


def init_db(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            done INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    db.execute("CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_user_ip ON login_attempts(username, ip_address)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)")

    db.commit()


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)