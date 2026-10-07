# Plataforma de solicitudes de soporte - Grupo 5 - Sprint 1
import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g, abort)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "clave-de-prueba-grupo5"
app.config["DB"] = "soporte.db"

CATEGORIAS = ["Hardware", "Software", "Red", "Accesos", "Otro"]
PRIORIDADES = ["Baja", "Media", "Alta"]
ORDENES = {
    "prioridad": "CASE s.prioridad WHEN 'Alta' THEN 1 WHEN 'Media' THEN 2 "
                 "WHEN 'Baja' THEN 3 ELSE 4 END",
    "estado": "s.estado",
    "fecha": "s.fecha DESC",
}


# ---------- base de datos ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DB"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(app.config["DB"])
    db.executescript("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT UNIQUE NOT NULL,
        clave_hash TEXT NOT NULL,
        rol TEXT NOT NULL,
        activo INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS solicitudes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL,
        descripcion TEXT NOT NULL,
        categoria TEXT NOT NULL,
        estado TEXT NOT NULL DEFAULT 'Nuevo',
        prioridad TEXT NOT NULL DEFAULT 'Sin definir',
        propietario_id INTEGER NOT NULL,
        fecha TEXT NOT NULL,
        actualizada TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS historial (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        solicitud_id INTEGER NOT NULL,
        usuario_id INTEGER NOT NULL,
        campo TEXT NOT NULL,
        valor_anterior TEXT,
        valor_nuevo TEXT,
        fecha TEXT NOT NULL
    );
    """)
    # datos semilla (ficticios)
    if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        semilla = [("solicitante1", "rol"), ("solicitante2", "rol"),
                   ("agente1", "agente"), ("coord1", "coordinador"),
                   ("auditor1", "auditor")]
        for usuario, rol in semilla:
            if rol == "rol":
                rol = "solicitante"
            db.execute("INSERT INTO usuarios (usuario, clave_hash, rol) VALUES (?,?,?)",
                       (usuario, generate_password_hash("Clave123*"), rol))
    db.commit()
    db.close()


def ahora():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- control de acceso ----------
def login_requerido(*roles):
    def decorador(f):
        @wraps(f)
        def envoltura(*args, **kwargs):
            if "usuario_id" not in session:
                return redirect(url_for("login"))
            if roles and session["rol"] not in roles:
                abort(403)
            return f(*args, **kwargs)
        return envoltura
    return decorador


# ---------- HU01: sesión ----------
@app.route("/")
def index():
    return redirect(url_for("inicio"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        clave = request.form.get("clave", "")
        u = get_db().execute("SELECT * FROM usuarios WHERE usuario = ? AND activo = 1",
                             (usuario,)).fetchone()
        # mismo mensaje si el usuario no existe o la clave está mal
        if u is None or not check_password_hash(u["clave_hash"], clave):
            flash("Usuario o contraseña incorrectos")
            return render_template("login.html"), 401
        session.clear()
        session["usuario_id"] = u["id"]
        session["usuario"] = u["usuario"]
        session["rol"] = u["rol"]
        return redirect(url_for("inicio"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/inicio")
@login_requerido()
def inicio():
    return render_template("inicio.html")


# ---------- HU02: crear solicitud ----------
@app.route("/solicitudes/nueva", methods=["GET", "POST"])
@login_requerido("solicitante")
def nueva():
    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        categoria = request.form.get("categoria", "")
        if not titulo or not descripcion or categoria not in CATEGORIAS:
            flash("Título, descripción y categoría son obligatorios")
            return render_template("nueva.html", categorias=CATEGORIAS), 400
        f = ahora()
        db = get_db()
        cur = db.execute(
            "INSERT INTO solicitudes (titulo, descripcion, categoria, propietario_id, fecha, actualizada) "
            "VALUES (?,?,?,?,?,?)",
            (titulo, descripcion, categoria, session["usuario_id"], f, f))
        db.commit()
        flash("Solicitud creada con ID %d" % cur.lastrowid)
        return redirect(url_for("detalle", id=cur.lastrowid))
    return render_template("nueva.html", categorias=CATEGORIAS)


# ---------- HU03 y HU04: listar ----------
@app.route("/solicitudes")
@login_requerido("solicitante", "coordinador")
def lista():
    db = get_db()
    if session["rol"] == "solicitante":
        filas = db.execute(
            "SELECT s.*, u.usuario FROM solicitudes s JOIN usuarios u ON u.id = s.propietario_id "
            "WHERE s.propietario_id = ? ORDER BY s.fecha DESC",
            (session["usuario_id"],)).fetchall()
        return render_template("lista.html", filas=filas, orden=None)
    orden = request.args.get("orden", "fecha")
    if orden not in ORDENES:
        orden = "fecha"
    filas = db.execute(
        "SELECT s.*, u.usuario FROM solicitudes s JOIN usuarios u ON u.id = s.propietario_id "
        "ORDER BY " + ORDENES[orden]).fetchall()
    return render_template("lista.html", filas=filas, orden=orden)


@app.route("/solicitudes/<int:id>")
@login_requerido("solicitante", "coordinador")
def detalle(id):
    db = get_db()
    s = db.execute("SELECT s.*, u.usuario FROM solicitudes s JOIN usuarios u "
                   "ON u.id = s.propietario_id WHERE s.id = ?", (id,)).fetchone()
    # si es ajena, el solicitante recibe 404 (no se revela que existe)
    if s is None or (session["rol"] == "solicitante" and s["propietario_id"] != session["usuario_id"]):
        abort(404)
    hist = db.execute("SELECT h.*, u.usuario FROM historial h JOIN usuarios u ON u.id = h.usuario_id "
                      "WHERE h.solicitud_id = ? ORDER BY h.id", (id,)).fetchall()
    return render_template("detalle.html", s=s, hist=hist, prioridades=PRIORIDADES)


# ---------- HU04: priorizar (solo coordinador) ----------
@app.route("/solicitudes/<int:id>/prioridad", methods=["POST"])
@login_requerido("coordinador")
def priorizar(id):
    nueva_p = request.form.get("prioridad", "")
    db = get_db()
    s = db.execute("SELECT * FROM solicitudes WHERE id = ?", (id,)).fetchone()
    if s is None:
        abort(404)
    if nueva_p not in PRIORIDADES:
        flash("Prioridad no válida")
        return redirect(url_for("detalle", id=id))
    if nueva_p != s["prioridad"]:
        f = ahora()
        db.execute("UPDATE solicitudes SET prioridad = ?, actualizada = ? WHERE id = ?",
                   (nueva_p, f, id))
        db.execute("INSERT INTO historial (solicitud_id, usuario_id, campo, valor_anterior, valor_nuevo, fecha) "
                   "VALUES (?,?,?,?,?,?)",
                   (id, session["usuario_id"], "prioridad", s["prioridad"], nueva_p, f))
        db.commit()
        flash("Prioridad actualizada")
    return redirect(url_for("detalle", id=id))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
