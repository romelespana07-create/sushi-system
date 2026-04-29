import csv
from datetime import datetime, timedelta
from functools import wraps
import hmac
import io
from pathlib import Path
import os
import re
import secrets
import socket
import sqlite3

from flask import (
    abort,
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "black-roll-sushi-local")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SESSION_HOURS", "10"))),
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024)),
)

DB_NAME = os.environ.get("DB_NAME", "sushi.db")
ULTIMO_RESPALDO_DIARIO = None
LOGIN_INTENTOS = {}
MAX_LOGIN_INTENTOS = int(os.environ.get("MAX_LOGIN_INTENTOS", "5"))
BLOQUEO_LOGIN_SEGUNDOS = int(os.environ.get("BLOQUEO_LOGIN_SEGUNDOS", "300"))
CSRF_FORM_RE = re.compile(
    r"(<form\b(?=[^>]*\bmethod=[\"']post[\"'])(?=[^>]*>)[^>]*>)",
    re.IGNORECASE,
)

MENU = [
    {"id": "california", "nombre": "California Roll", "precio": 120, "categoria": "Rolls"},
    {"id": "philadelphia", "nombre": "Philadelphia Roll", "precio": 130, "categoria": "Rolls"},
    {"id": "empanizado", "nombre": "Empanizado", "precio": 140, "categoria": "Rolls"},
    {"id": "ramen", "nombre": "Ramen", "precio": 150, "categoria": "Cocina"},
    {"id": "gyozas", "nombre": "Gyozas", "precio": 95, "categoria": "Entradas"},
    {"id": "te_helado", "nombre": "Te helado", "precio": 45, "categoria": "Bebidas"},
]

METODOS_PAGO = [
    {"id": "efectivo", "nombre": "Efectivo"},
    {"id": "transferencia", "nombre": "Transferencia"},
    {"id": "tarjeta", "nombre": "Tarjeta"},
    {"id": "cortesia", "nombre": "Cortesia"},
]

def configurar_usuario(clave, password_default, rol, nombre):
    prefijo = clave.upper()
    return {
        "password": os.environ.get(f"{prefijo}_PASSWORD", password_default),
        "password_hash": os.environ.get(f"{prefijo}_PASSWORD_HASH", ""),
        "rol": rol,
        "nombre": nombre,
    }


USUARIOS = {
    "caja": configurar_usuario("caja", "caja123", "caja", "Caja"),
    "cocina": configurar_usuario("cocina", "cocina123", "cocina", "Cocina"),
    "empanizado": configurar_usuario("empanizado", "empanizado123", "empanizado", "Empanizado"),
    "decoracion": configurar_usuario("decoracion", "decoracion123", "decoracion", "Decoracion"),
    "admin": configurar_usuario("admin", "admin123", "administrador", "Administrador"),
}

ETAPAS = {
    "armado_pendiente": "Armado",
    "empanizado_pendiente": "Empanizado",
    "decoracion_pendiente": "Decoracion",
    "listo": "Listo",
}

PREPARACIONES = [
    {"id": "natural", "nombre": "Natural"},
    {"id": "empanizado", "nombre": "Empanizado"},
]

QUITAR_OPCIONES = [
    "Sin alga",
    "Sin camaron",
    "Sin spicy",
    "Sin anguila",
    "Sin ajonjoli",
]

TERMINADO_OPCIONES = [
    "Extra queso",
    "Spicy encima",
    "Anguila encima",
    "Tampico",
    "Salsa especial",
    "Ajonjoli",
    "Decoracion especial",
]

POR_DENTRO_OPCIONES = [
    "Pollo",
    "Salmon",
    "Camaron",
    "Queso",
]

INVENTARIO_INICIAL = {
    "arroz": {"unidad": "g", "stock": 8000},
    "alga": {"unidad": "hojas", "stock": 120},
    "queso": {"unidad": "g", "stock": 3500},
    "camaron": {"unidad": "g", "stock": 4200},
    "salmon": {"unidad": "g", "stock": 3800},
}

RECETAS = {
    "california": {"arroz": 120, "alga": 1, "queso": 25, "camaron": 70},
    "philadelphia": {"arroz": 120, "alga": 1, "queso": 35, "salmon": 80},
    "empanizado": {"arroz": 130, "alga": 1, "queso": 25, "camaron": 80},
}


def password_usuario_valida(datos, password):
    if datos.get("password_hash"):
        return check_password_hash(datos["password_hash"], password)
    return hmac.compare_digest(datos.get("password", ""), password)


def clave_intento_login(usuario):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "local").split(",")[0].strip()
    return f"{ip}:{usuario or 'sin_usuario'}"


def segundos_bloqueo_login(usuario):
    clave = clave_intento_login(usuario)
    intento = LOGIN_INTENTOS.get(clave)
    if not intento:
        return 0

    bloqueado_hasta = intento.get("bloqueado_hasta")
    ahora = datetime.now()
    if bloqueado_hasta and bloqueado_hasta > ahora:
        return int((bloqueado_hasta - ahora).total_seconds())

    if bloqueado_hasta:
        LOGIN_INTENTOS.pop(clave, None)
    return 0


def registrar_login_fallido(usuario):
    clave = clave_intento_login(usuario)
    intento = LOGIN_INTENTOS.setdefault(clave, {"intentos": 0, "bloqueado_hasta": None})
    intento["intentos"] += 1
    if intento["intentos"] >= MAX_LOGIN_INTENTOS:
        intento["bloqueado_hasta"] = datetime.now() + timedelta(seconds=BLOQUEO_LOGIN_SEGUNDOS)


def limpiar_intentos_login(usuario):
    LOGIN_INTENTOS.pop(clave_intento_login(usuario), None)


def obtener_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def agregar_csrf_a_forms(html):
    token = obtener_csrf_token()
    hidden = f'<input type="hidden" name="csrf_token" value="{token}">'
    return CSRF_FORM_RE.sub(lambda match: match.group(1) + hidden, html)


def validar_csrf():
    esperado = session.get("csrf_token")
    recibido = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not esperado or not recibido or not hmac.compare_digest(esperado, recibido):
        abort(400)


def conectar_db():
    db_path = Path(DB_NAME)
    if db_path.parent != Path("."):
        db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def columna_existe(conn, tabla, columna):
    columnas = conn.execute(f"PRAGMA table_info({tabla})").fetchall()
    return any(item["name"] == columna for item in columnas)


def asegurar_columna(conn, tabla, definicion):
    columna = definicion.split()[0]
    if not columna_existe(conn, tabla, columna):
        conn.execute(f"ALTER TABLE {tabla} ADD COLUMN {definicion}")


def crear_tablas():
    conn = conectar_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pedidos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente TEXT NOT NULL,
            telefono TEXT NOT NULL DEFAULT '',
            estado TEXT NOT NULL DEFAULT 'pendiente',
            total INTEGER NOT NULL DEFAULT 0,
            fecha TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pedido_productos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pedido_id INTEGER NOT NULL,
            producto_id TEXT NOT NULL DEFAULT '',
            producto TEXT NOT NULL,
            precio INTEGER NOT NULL,
            cantidad INTEGER NOT NULL DEFAULT 1,
            preparacion TEXT NOT NULL DEFAULT 'natural',
            por_dentro TEXT NOT NULL DEFAULT '',
            quitar TEXT NOT NULL DEFAULT '',
            extras TEXT NOT NULL DEFAULT '',
            terminado TEXT NOT NULL DEFAULT '',
            notas TEXT NOT NULL DEFAULT '',
            etapa TEXT NOT NULL DEFAULT 'armado_pendiente',
            FOREIGN KEY (pedido_id) REFERENCES pedidos(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ventas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            folio TEXT NOT NULL DEFAULT '',
            cliente TEXT NOT NULL,
            telefono TEXT NOT NULL DEFAULT '',
            total INTEGER NOT NULL,
            metodo_pago TEXT NOT NULL DEFAULT 'efectivo',
            fecha TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS venta_productos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            venta_id INTEGER NOT NULL,
            producto TEXT NOT NULL,
            precio INTEGER NOT NULL,
            cantidad INTEGER NOT NULL,
            preparacion TEXT NOT NULL DEFAULT 'natural',
            por_dentro TEXT NOT NULL DEFAULT '',
            quitar TEXT NOT NULL DEFAULT '',
            extras TEXT NOT NULL DEFAULT '',
            terminado TEXT NOT NULL DEFAULT '',
            notas TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (venta_id) REFERENCES ventas(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS inventario (
            ingrediente TEXT PRIMARY KEY,
            unidad TEXT NOT NULL,
            stock REAL NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS etapa_historial (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pedido_id INTEGER NOT NULL,
            linea_id INTEGER NOT NULL,
            folio TEXT NOT NULL,
            cliente TEXT NOT NULL,
            producto TEXT NOT NULL,
            cantidad INTEGER NOT NULL DEFAULT 1,
            etapa TEXT NOT NULL,
            fecha_entrada TEXT NOT NULL,
            fecha_salida TEXT,
            duracion_minutos REAL,
            usuario_salida TEXT NOT NULL DEFAULT '',
            rol_salida TEXT NOT NULL DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_etapa_historial_linea
        ON etapa_historial (linea_id, etapa, fecha_salida)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_etapa_historial_fecha
        ON etapa_historial (fecha_entrada, etapa)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_pedidos_estado_id
        ON pedidos (estado, id DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_pedido_productos_pedido
        ON pedido_productos (pedido_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_pedido_productos_etapa
        ON pedido_productos (etapa, pedido_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_ventas_fecha
        ON ventas (fecha)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_venta_productos_venta
        ON venta_productos (venta_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_venta_productos_producto
        ON venta_productos (producto)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_etapa_historial_salida
        ON etapa_historial (fecha_salida, etapa)
    """)

    asegurar_columna(conn, "pedidos", "telefono TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "pedido_productos", "producto_id TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "pedido_productos", "cantidad INTEGER NOT NULL DEFAULT 1")
    asegurar_columna(conn, "pedido_productos", "preparacion TEXT NOT NULL DEFAULT 'natural'")
    asegurar_columna(conn, "pedido_productos", "por_dentro TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "pedido_productos", "quitar TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "pedido_productos", "extras TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "pedido_productos", "terminado TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "pedido_productos", "notas TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "pedido_productos", "etapa TEXT NOT NULL DEFAULT 'armado_pendiente'")
    asegurar_columna(conn, "ventas", "folio TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "ventas", "telefono TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "ventas", "metodo_pago TEXT NOT NULL DEFAULT 'efectivo'")
    asegurar_columna(conn, "venta_productos", "preparacion TEXT NOT NULL DEFAULT 'natural'")
    asegurar_columna(conn, "venta_productos", "por_dentro TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "venta_productos", "quitar TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "venta_productos", "extras TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "venta_productos", "terminado TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "venta_productos", "notas TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "etapa_historial", "usuario_salida TEXT NOT NULL DEFAULT ''")
    asegurar_columna(conn, "etapa_historial", "rol_salida TEXT NOT NULL DEFAULT ''")

    cursor.execute("""
        UPDATE pedido_productos
        SET etapa = 'listo'
        WHERE pedido_id IN (
            SELECT id FROM pedidos WHERE estado = 'listo'
        )
        AND etapa = 'armado_pendiente'
    """)

    for ingrediente, datos in INVENTARIO_INICIAL.items():
        cursor.execute("""
            INSERT OR IGNORE INTO inventario (ingrediente, unidad, stock)
            VALUES (?, ?, ?)
        """, (ingrediente, datos["unidad"], datos["stock"]))

    cursor.execute("""
        INSERT INTO etapa_historial (
            pedido_id, linea_id, folio, cliente, producto, cantidad,
            etapa, fecha_entrada, fecha_salida, duracion_minutos
        )
        SELECT
            pedidos.id,
            pedido_productos.id,
            'BR-' || printf('%04d', pedidos.id),
            pedidos.cliente,
            pedido_productos.producto,
            pedido_productos.cantidad,
            pedido_productos.etapa,
            pedidos.fecha,
            NULL,
            NULL
        FROM pedido_productos
        JOIN pedidos ON pedidos.id = pedido_productos.pedido_id
        WHERE pedido_productos.etapa != 'listo'
          AND NOT EXISTS (
              SELECT 1
              FROM etapa_historial
              WHERE etapa_historial.linea_id = pedido_productos.id
                AND etapa_historial.etapa = pedido_productos.etapa
                AND etapa_historial.fecha_salida IS NULL
          )
    """)

    conn.commit()
    conn.close()


def buscar_producto(valor):
    for item in MENU:
        if item["id"] == valor or item["nombre"] == valor:
            return item
    return None


def menu_por_categoria():
    categorias = {}
    for item in MENU:
        categorias.setdefault(item["categoria"], []).append(item)
    return categorias


def producto_requiere_armado(producto):
    return producto["categoria"] in ("Rolls", "Cocina", "Entradas")


def producto_requiere_decoracion(producto):
    return producto["categoria"] == "Rolls"


def etapa_inicial_producto(producto):
    if producto_requiere_armado(producto):
        return "armado_pendiente"
    return "listo"


def siguiente_etapa_despues_armado(producto_id, preparacion="natural"):
    producto = buscar_producto(producto_id)
    if producto and producto_requiere_decoracion(producto):
        if preparacion == "empanizado":
            return "empanizado_pendiente"
        return "decoracion_pendiente"
    return "listo"


def siguiente_etapa_producto(linea):
    etapa_actual = linea["etapa"]

    if etapa_actual == "armado_pendiente":
        return siguiente_etapa_despues_armado(linea["producto_id"], linea["preparacion"])
    if etapa_actual == "empanizado_pendiente":
        return "decoracion_pendiente"
    if etapa_actual == "decoracion_pendiente":
        return "listo"
    return etapa_actual


def rol_puede_avanzar(etapa_actual):
    rol = session.get("rol")
    if rol == "administrador":
        return True
    permisos = {
        "armado_pendiente": "cocina",
        "empanizado_pendiente": "empanizado",
        "decoracion_pendiente": "decoracion",
    }
    return permisos.get(etapa_actual) == rol


def etapa_nombre(etapa):
    return ETAPAS.get(etapa, etapa.replace("_", " ").title())


def combinar_opciones(opciones, texto_extra=""):
    valores = [opcion.strip() for opcion in opciones if opcion.strip()]
    if texto_extra.strip():
        valores.append(texto_extra.strip())
    return ", ".join(valores)


def minutos_abierto(fecha):
    try:
        inicio = datetime.strptime(fecha, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return 0
    minutos = int((datetime.now() - inicio).total_seconds() // 60)
    return max(minutos, 0)


def texto_tiempo(minutos):
    if minutos < 1:
        return "Nuevo"
    if minutos < 60:
        return f"{minutos} min"
    horas = minutos // 60
    resto = minutos % 60
    if resto:
        return f"{horas} h {resto} min"
    return f"{horas} h"


def fecha_actual():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def duracion_minutos(fecha_entrada, fecha_salida):
    try:
        entrada = datetime.strptime(fecha_entrada, "%Y-%m-%d %H:%M:%S")
        salida = datetime.strptime(fecha_salida, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return 0
    return round(max((salida - entrada).total_seconds(), 0) / 60, 2)


def estado_carga(piezas_activas, piezas_nuevas_10, alta_activos=10, saturado_activos=20, alta_nuevos=8, saturado_nuevos=14):
    if piezas_activas >= saturado_activos or piezas_nuevas_10 >= saturado_nuevos:
        return {
            "id": "saturado",
            "label": "Saturado",
            "mensaje": "Conviene meter apoyo o avisar mas tiempo.",
        }

    if piezas_activas >= alta_activos or piezas_nuevas_10 >= alta_nuevos:
        return {
            "id": "alta",
            "label": "Alta demanda",
            "mensaje": "Flujo cargado; conviene vigilar prioridades.",
        }

    return {
        "id": "normal",
        "label": "Carga normal",
        "mensaje": "Flujo estable.",
    }


def usuario_actual():
    try:
        return session.get("usuario") or "Sistema"
    except RuntimeError:
        return "Sistema"


def rol_actual():
    try:
        return session.get("rol") or "sistema"
    except RuntimeError:
        return "sistema"


def obtener_linea_para_historial(conn, linea_id):
    return conn.execute("""
        SELECT
            pedido_productos.id,
            pedido_productos.pedido_id,
            pedido_productos.producto,
            pedido_productos.cantidad,
            pedido_productos.etapa,
            pedidos.cliente
        FROM pedido_productos
        JOIN pedidos ON pedidos.id = pedido_productos.pedido_id
        WHERE pedido_productos.id = ?
    """, (linea_id,)).fetchone()


def abrir_historial_etapa(conn, linea_id, etapa=None, fecha_entrada=None):
    linea = obtener_linea_para_historial(conn, linea_id)
    if linea is None:
        return

    etapa = etapa or linea["etapa"]
    if etapa == "listo":
        return

    abierto = conn.execute("""
        SELECT id
        FROM etapa_historial
        WHERE linea_id = ?
          AND etapa = ?
          AND fecha_salida IS NULL
        ORDER BY id DESC
        LIMIT 1
    """, (linea_id, etapa)).fetchone()

    if abierto:
        conn.execute("""
            UPDATE etapa_historial
            SET cantidad = ?, producto = ?, cliente = ?
            WHERE id = ?
        """, (linea["cantidad"], linea["producto"], linea["cliente"], abierto["id"]))
        return

    conn.execute("""
        INSERT INTO etapa_historial (
            pedido_id, linea_id, folio, cliente, producto, cantidad,
            etapa, fecha_entrada, fecha_salida, duracion_minutos
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
    """, (
        linea["pedido_id"],
        linea["id"],
        folio_pedido(linea["pedido_id"]),
        linea["cliente"],
        linea["producto"],
        linea["cantidad"],
        etapa,
        fecha_entrada or fecha_actual(),
    ))


def sincronizar_historial_abierto(conn, linea_id):
    linea = obtener_linea_para_historial(conn, linea_id)
    if linea is None:
        return

    conn.execute("""
        UPDATE etapa_historial
        SET cantidad = ?, producto = ?, cliente = ?
        WHERE linea_id = ?
          AND fecha_salida IS NULL
    """, (linea["cantidad"], linea["producto"], linea["cliente"], linea_id))


def cerrar_historial_etapa(conn, linea_id, etapa, fecha_salida=None):
    fecha_salida = fecha_salida or fecha_actual()
    usuario = usuario_actual()
    rol = rol_actual()
    registros = conn.execute("""
        SELECT id, fecha_entrada
        FROM etapa_historial
        WHERE linea_id = ?
          AND etapa = ?
          AND fecha_salida IS NULL
    """, (linea_id, etapa)).fetchall()

    for registro in registros:
        conn.execute("""
            UPDATE etapa_historial
            SET fecha_salida = ?,
                duracion_minutos = ?,
                usuario_salida = ?,
                rol_salida = ?
            WHERE id = ?
        """, (
            fecha_salida,
            duracion_minutos(registro["fecha_entrada"], fecha_salida),
            usuario,
            rol,
            registro["id"],
        ))


def cerrar_historial_abierto_linea(conn, linea_id):
    fecha_salida = fecha_actual()
    usuario = usuario_actual()
    rol = rol_actual()
    registros = conn.execute("""
        SELECT id, fecha_entrada
        FROM etapa_historial
        WHERE linea_id = ?
          AND fecha_salida IS NULL
    """, (linea_id,)).fetchall()

    for registro in registros:
        conn.execute("""
            UPDATE etapa_historial
            SET fecha_salida = ?,
                duracion_minutos = ?,
                usuario_salida = ?,
                rol_salida = ?
            WHERE id = ?
        """, (
            fecha_salida,
            duracion_minutos(registro["fecha_entrada"], fecha_salida),
            usuario,
            rol,
            registro["id"],
        ))


def cerrar_historial_abierto_pedido(conn, pedido_id):
    fecha_salida = fecha_actual()
    usuario = usuario_actual()
    rol = rol_actual()
    registros = conn.execute("""
        SELECT id, fecha_entrada
        FROM etapa_historial
        WHERE pedido_id = ?
          AND fecha_salida IS NULL
    """, (pedido_id,)).fetchall()

    for registro in registros:
        conn.execute("""
            UPDATE etapa_historial
            SET fecha_salida = ?,
                duracion_minutos = ?,
                usuario_salida = ?,
                rol_salida = ?
            WHERE id = ?
        """, (
            fecha_salida,
            duracion_minutos(registro["fecha_entrada"], fecha_salida),
            usuario,
            rol,
            registro["id"],
        ))


def cambiar_etapa_producto(conn, linea_id, nueva_etapa):
    linea = obtener_linea_para_historial(conn, linea_id)
    if linea is None:
        return None

    etapa_anterior = linea["etapa"]
    if etapa_anterior == nueva_etapa:
        sincronizar_historial_abierto(conn, linea_id)
        return etapa_anterior

    fecha_cambio = fecha_actual()
    abrir_historial_etapa(conn, linea_id, etapa_anterior)
    cerrar_historial_etapa(conn, linea_id, etapa_anterior, fecha_cambio)

    conn.execute("""
        UPDATE pedido_productos
        SET etapa = ?
        WHERE id = ?
    """, (nueva_etapa, linea_id))

    if nueva_etapa != "listo":
        abrir_historial_etapa(conn, linea_id, nueva_etapa, fecha_cambio)

    return nueva_etapa


def estado_pedido_desde_productos(productos):
    etapas = [producto["etapa"] for producto in productos]
    if not etapas:
        return "pendiente"
    if any(etapa == "armado_pendiente" for etapa in etapas):
        return "armado"
    if any(etapa == "empanizado_pendiente" for etapa in etapas):
        return "empanizado"
    if any(etapa == "decoracion_pendiente" for etapa in etapas):
        return "decoracion"
    if all(etapa == "listo" for etapa in etapas):
        return "listo"
    return "pendiente"


def actualizar_estado_pedido(conn, pedido_id):
    productos = obtener_productos_pedido(conn, pedido_id)
    estado = estado_pedido_desde_productos(productos)
    conn.execute("""
        UPDATE pedidos
        SET estado = ?
        WHERE id = ?
    """, (estado, pedido_id))
    return estado


def metodo_nombre(metodo_id):
    for metodo in METODOS_PAGO:
        if metodo["id"] == metodo_id:
            return metodo["nombre"]
    return metodo_id.title()


def folio_pedido(pedido_id):
    return f"BR-{pedido_id:04d}"


def contar_por_estado(pedidos):
    conteo = {"pendiente": 0, "armado": 0, "empanizado": 0, "decoracion": 0, "listo": 0}
    for pedido in pedidos:
        if pedido["estado"] in conteo:
            conteo[pedido["estado"]] += 1
        else:
            conteo["pendiente"] += 1
    return conteo


def obtener_pedidos():
    conn = conectar_db()
    cursor = conn.cursor()

    pedidos_db = cursor.execute("""
        SELECT *
        FROM pedidos
        ORDER BY
            CASE estado
                WHEN 'armado' THEN 1
                WHEN 'pendiente' THEN 1
                WHEN 'empanizado' THEN 2
                WHEN 'decoracion' THEN 3
                WHEN 'listo' THEN 4
                ELSE 5
            END,
            id DESC
    """).fetchall()

    pedidos = []
    for pedido in pedidos_db:
        productos = cursor.execute("""
            SELECT id, producto_id, producto, precio, cantidad,
                   preparacion, por_dentro, quitar, extras, terminado, notas, etapa
            FROM pedido_productos
            WHERE pedido_id = ?
            ORDER BY id
        """, (pedido["id"],)).fetchall()
        estado = estado_pedido_desde_productos(productos)
        total_items = sum(producto["cantidad"] for producto in productos)
        edad_minutos = minutos_abierto(pedido["fecha"])

        pedidos.append({
            "id": pedido["id"],
            "folio": folio_pedido(pedido["id"]),
            "cliente": pedido["cliente"],
            "telefono": pedido["telefono"],
            "estado": estado,
            "total": pedido["total"],
            "fecha": pedido["fecha"],
            "productos": productos,
            "total_items": total_items,
            "edad_minutos": edad_minutos,
            "edad_texto": texto_tiempo(edad_minutos),
        })

    conn.close()
    return pedidos


def obtener_pedidos_por_etapa(etapa):
    conn = conectar_db()
    cursor = conn.cursor()

    pedidos_db = cursor.execute("""
        SELECT DISTINCT pedidos.*
        FROM pedidos
        JOIN pedido_productos ON pedido_productos.pedido_id = pedidos.id
        WHERE pedido_productos.etapa = ?
        GROUP BY pedidos.id
        ORDER BY SUM(pedido_productos.cantidad) DESC, pedidos.fecha ASC
    """, (etapa,)).fetchall()

    pedidos = []
    for pedido in pedidos_db:
        productos_db = cursor.execute("""
            SELECT id, producto_id, producto, precio, cantidad,
                   preparacion, por_dentro, quitar, extras, terminado, notas, etapa,
                   (
                       SELECT fecha_entrada
                       FROM etapa_historial
                       WHERE etapa_historial.linea_id = pedido_productos.id
                         AND etapa_historial.etapa = pedido_productos.etapa
                         AND etapa_historial.fecha_salida IS NULL
                       ORDER BY etapa_historial.id DESC
                       LIMIT 1
                   ) AS fecha_entrada_etapa
            FROM pedido_productos
            WHERE pedido_id = ? AND etapa = ?
            ORDER BY id
        """, (pedido["id"], etapa)).fetchall()

        productos = []
        for producto in productos_db:
            producto_dict = dict(producto)
            minutos_etapa = minutos_abierto(producto_dict["fecha_entrada_etapa"]) if producto_dict["fecha_entrada_etapa"] else minutos_abierto(pedido["fecha"])
            producto_dict["minutos_etapa"] = minutos_etapa
            producto_dict["tiempo_etapa"] = texto_tiempo(minutos_etapa)
            producto_dict["alerta_etapa"] = ""
            productos.append(producto_dict)

        total_items = sum(producto["cantidad"] for producto in productos)
        edad_minutos = minutos_abierto(pedido["fecha"])
        max_minutos_etapa = max((producto["minutos_etapa"] for producto in productos), default=0)

        pedidos.append({
            "id": pedido["id"],
            "folio": folio_pedido(pedido["id"]),
            "cliente": pedido["cliente"],
            "telefono": pedido["telefono"],
            "estado": estado_pedido_desde_productos(productos),
            "total": pedido["total"],
            "fecha": pedido["fecha"],
            "productos": productos,
            "total_items": total_items,
            "edad_minutos": edad_minutos,
            "edad_texto": texto_tiempo(edad_minutos),
            "max_minutos_etapa": max_minutos_etapa,
        })

    conn.close()
    return pedidos


def contar_lineas_por_etapa():
    conn = conectar_db()
    conteo = {etapa: 0 for etapa in ETAPAS}
    filas = conn.execute("""
        SELECT etapa, COALESCE(SUM(cantidad), 0) AS total
        FROM pedido_productos
        GROUP BY etapa
    """).fetchall()

    for fila in filas:
        conteo[fila["etapa"]] = fila["total"]

    conn.close()
    return conteo


def obtener_pedido(conn, pedido_id):
    return conn.execute("""
        SELECT *
        FROM pedidos
        WHERE id = ?
    """, (pedido_id,)).fetchone()


def obtener_productos_pedido(conn, pedido_id):
    return conn.execute("""
        SELECT id, producto_id, producto, precio, cantidad,
               preparacion, por_dentro, quitar, extras, terminado, notas, etapa
        FROM pedido_productos
        WHERE pedido_id = ?
        ORDER BY id
    """, (pedido_id,)).fetchall()


def recalcular_total(conn, pedido_id):
    total = conn.execute("""
        SELECT COALESCE(SUM(precio * cantidad), 0) AS total
        FROM pedido_productos
        WHERE pedido_id = ?
    """, (pedido_id,)).fetchone()["total"]

    conn.execute("""
        UPDATE pedidos
        SET total = ?
        WHERE id = ?
    """, (total, pedido_id))
    return total


def borrar_pedido(conn, pedido_id):
    cerrar_historial_abierto_pedido(conn, pedido_id)
    conn.execute("DELETE FROM pedido_productos WHERE pedido_id = ?", (pedido_id,))
    conn.execute("DELETE FROM pedidos WHERE id = ?", (pedido_id,))


def agregar_producto_a_pedido(conn, pedido_id, producto, modificadores):
    etapa = etapa_inicial_producto(producto)
    linea = conn.execute("""
        SELECT id, cantidad
        FROM pedido_productos
        WHERE pedido_id = ?
          AND producto_id = ?
          AND preparacion = ?
          AND por_dentro = ?
          AND quitar = ?
          AND extras = ?
          AND terminado = ?
          AND notas = ?
          AND etapa = ?
    """, (
        pedido_id,
        producto["id"],
        modificadores["preparacion"],
        modificadores["por_dentro"],
        modificadores["quitar"],
        modificadores["extras"],
        modificadores["terminado"],
        modificadores["notas"],
        etapa,
    )).fetchone()

    if linea:
        conn.execute("""
            UPDATE pedido_productos
            SET cantidad = cantidad + 1
            WHERE id = ?
        """, (linea["id"],))
        sincronizar_historial_abierto(conn, linea["id"])
    else:
        cursor = conn.execute("""
            INSERT INTO pedido_productos (
                pedido_id, producto_id, producto, precio, cantidad,
                preparacion, por_dentro, quitar, extras, terminado, notas, etapa
            )
            VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pedido_id,
            producto["id"],
            producto["nombre"],
            producto["precio"],
            modificadores["preparacion"],
            modificadores["por_dentro"],
            modificadores["quitar"],
            modificadores["extras"],
            modificadores["terminado"],
            modificadores["notas"],
            etapa,
        ))
        abrir_historial_etapa(conn, cursor.lastrowid, etapa)

    recalcular_total(conn, pedido_id)
    actualizar_estado_pedido(conn, pedido_id)


def inventario_requerido(productos):
    requerido = {}
    for producto in productos:
        producto_id = producto["producto_id"] or (buscar_producto(producto["producto"]) or {}).get("id", "")
        receta = RECETAS.get(producto_id, {})
        quitar = (producto["quitar"] or "").lower()
        for ingrediente, cantidad in receta.items():
            if ingrediente in quitar:
                continue
            requerido[ingrediente] = requerido.get(ingrediente, 0) + (cantidad * producto["cantidad"])
    return requerido


def validar_inventario(conn, productos):
    faltantes = []
    requerido = inventario_requerido(productos)

    for ingrediente, cantidad in requerido.items():
        item = conn.execute("""
            SELECT ingrediente, unidad, stock
            FROM inventario
            WHERE ingrediente = ?
        """, (ingrediente,)).fetchone()

        stock = item["stock"] if item else 0
        unidad = item["unidad"] if item else ""
        if stock < cantidad:
            faltantes.append({
                "ingrediente": ingrediente,
                "faltan": round(cantidad - stock, 2),
                "unidad": unidad,
            })

    return faltantes


def descontar_inventario(conn, productos):
    requerido = inventario_requerido(productos)
    for ingrediente, cantidad in requerido.items():
        conn.execute("""
            UPDATE inventario
            SET stock = stock - ?
            WHERE ingrediente = ?
        """, (cantidad, ingrediente))


def obtener_ventas(fecha=None):
    conn = conectar_db()
    cursor = conn.cursor()

    fecha = fecha or datetime.now().strftime("%Y-%m-%d")
    filtro = fecha + "%"

    ventas_db = cursor.execute("""
        SELECT *
        FROM ventas
        WHERE fecha LIKE ?
        ORDER BY id DESC
    """, (filtro,)).fetchall()

    total_ventas = cursor.execute("""
        SELECT COALESCE(SUM(total), 0) AS total
        FROM ventas
        WHERE fecha LIKE ?
    """, (filtro,)).fetchone()["total"]

    total_ingresos = cursor.execute("""
        SELECT COALESCE(SUM(CASE WHEN metodo_pago != 'cortesia' THEN total ELSE 0 END), 0) AS total
        FROM ventas
        WHERE fecha LIKE ?
    """, (filtro,)).fetchone()["total"]

    totales_metodo = {metodo["id"]: 0 for metodo in METODOS_PAGO}
    rows = cursor.execute("""
        SELECT metodo_pago, COALESCE(SUM(total), 0) AS total
        FROM ventas
        WHERE fecha LIKE ?
        GROUP BY metodo_pago
    """, (filtro,)).fetchall()

    for row in rows:
        totales_metodo[row["metodo_pago"]] = row["total"]

    conn.close()
    return ventas_db, total_ventas, total_ingresos, totales_metodo, fecha


def obtener_venta(venta_id):
    conn = conectar_db()
    venta = conn.execute("""
        SELECT *
        FROM ventas
        WHERE id = ?
    """, (venta_id,)).fetchone()

    productos = conn.execute("""
        SELECT *
        FROM venta_productos
        WHERE venta_id = ?
        ORDER BY id
    """, (venta_id,)).fetchall()

    conn.close()
    return venta, productos


def obtener_inventario():
    conn = conectar_db()
    inventario = conn.execute("""
        SELECT *
        FROM inventario
        ORDER BY ingrediente
    """).fetchall()
    conn.close()
    return inventario


def obtener_ip_local():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def ruta_db():
    origen = Path(DB_NAME)
    if not origen.is_absolute():
        origen = Path.cwd() / origen
    return origen


def crear_respaldo_db(nombre_archivo=None):
    origen = ruta_db()

    carpeta = origen.parent / "backups"
    carpeta.mkdir(exist_ok=True)
    nombre_archivo = nombre_archivo or f"sushi-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    destino = carpeta / nombre_archivo

    source = sqlite3.connect(origen)
    backup = sqlite3.connect(destino)
    try:
        source.backup(backup)
    finally:
        backup.close()
        source.close()

    return destino


def asegurar_respaldo_diario():
    global ULTIMO_RESPALDO_DIARIO

    if os.environ.get("AUTO_BACKUP", "1") != "1":
        return None

    hoy = datetime.now().strftime("%Y%m%d")
    if ULTIMO_RESPALDO_DIARIO == hoy:
        return None

    destino = ruta_db().parent / "backups" / f"sushi-auto-{hoy}.db"
    if not destino.exists():
        crear_respaldo_db(destino.name)

    ULTIMO_RESPALDO_DIARIO = hoy
    return destino


def exportar_ventas_csv(fecha):
    ventas, total_ventas, total_ingresos, totales_metodo, fecha = obtener_ventas(fecha)
    conn = conectar_db()

    salida = io.StringIO()
    salida.write("\ufeff")
    writer = csv.writer(salida)
    writer.writerow([
        "folio",
        "fecha",
        "cliente",
        "telefono",
        "metodo_pago",
        "total",
        "productos",
    ])

    for venta in ventas:
        productos = conn.execute("""
            SELECT producto, cantidad
            FROM venta_productos
            WHERE venta_id = ?
            ORDER BY id
        """, (venta["id"],)).fetchall()
        detalle = " | ".join(f"{item['producto']} x{item['cantidad']}" for item in productos)
        writer.writerow([
            venta["folio"] or folio_pedido(venta["id"]),
            venta["fecha"],
            venta["cliente"],
            venta["telefono"] or "",
            metodo_nombre(venta["metodo_pago"]),
            venta["total"],
            detalle,
        ])

    writer.writerow([])
    writer.writerow(["Total vendido", total_ventas])
    writer.writerow(["Total ingresos", total_ingresos])
    for metodo in METODOS_PAGO:
        writer.writerow([f"Total {metodo['nombre']}", totales_metodo.get(metodo["id"], 0)])

    conn.close()
    return salida.getvalue()


def obtener_dashboard_negocio(fecha=None):
    conn = conectar_db()
    fecha = fecha or datetime.now().strftime("%Y-%m-%d")
    filtro = fecha + "%"

    ventas_resumen = conn.execute("""
        SELECT COUNT(*) AS tickets,
               COALESCE(SUM(total), 0) AS vendido,
               COALESCE(SUM(CASE WHEN metodo_pago != 'cortesia' THEN total ELSE 0 END), 0) AS ingresos
        FROM ventas
        WHERE fecha LIKE ?
    """, (filtro,)).fetchone()

    pedidos_abiertos = conn.execute("""
        SELECT COUNT(*) AS pedidos,
               COALESCE(SUM(total), 0) AS total_abierto
        FROM pedidos
    """).fetchone()

    piezas_abiertas = conn.execute("""
        SELECT COALESCE(SUM(cantidad), 0) AS piezas
        FROM pedido_productos
        WHERE etapa != 'listo'
    """).fetchone()["piezas"]

    limite_10_min = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    piezas_nuevas_10 = conn.execute("""
        SELECT COALESCE(SUM(cantidad), 0) AS piezas
        FROM etapa_historial
        WHERE fecha_salida IS NULL
          AND fecha_entrada >= ?
    """, (limite_10_min,)).fetchone()["piezas"]

    productos = conn.execute("""
        SELECT
            venta_productos.producto,
            SUM(venta_productos.cantidad) AS vendidos,
            SUM(venta_productos.precio * venta_productos.cantidad) AS ingresos,
            ROUND(AVG(venta_productos.precio), 2) AS precio_promedio
        FROM venta_productos
        JOIN ventas ON ventas.id = venta_productos.venta_id
        WHERE ventas.fecha LIKE ?
        GROUP BY venta_productos.producto
        ORDER BY vendidos DESC, ingresos DESC
    """, (filtro,)).fetchall()

    tiempos_producto = conn.execute("""
        SELECT producto,
               ROUND(AVG(tiempo_total), 2) AS promedio_total
        FROM (
            SELECT linea_id,
                   producto,
                   SUM(duracion_minutos) AS tiempo_total
            FROM etapa_historial
            WHERE fecha_salida LIKE ?
              AND duracion_minutos IS NOT NULL
            GROUP BY linea_id, producto
        )
        GROUP BY producto
    """, (filtro,)).fetchall()

    tiempos = {row["producto"]: row["promedio_total"] or 0 for row in tiempos_producto}
    productos_menu = []
    for row in productos:
        item = dict(row)
        item["tiempo_promedio"] = tiempos.get(item["producto"], 0)
        productos_menu.append(item)

    producto_mas_vendido = productos_menu[0] if productos_menu else None
    producto_mayor_ingreso = max(productos_menu, key=lambda item: item["ingresos"], default=None)
    producto_mas_lento = max(productos_menu, key=lambda item: item["tiempo_promedio"], default=None)

    tickets = ventas_resumen["tickets"] or 0
    ingresos = ventas_resumen["ingresos"] or 0
    vendido = ventas_resumen["vendido"] or 0
    ticket_promedio = round(ingresos / tickets, 2) if tickets else 0
    carga_negocio = estado_carga(
        piezas_abiertas or 0,
        piezas_nuevas_10 or 0,
        alta_activos=25,
        saturado_activos=45,
        alta_nuevos=15,
        saturado_nuevos=25,
    )

    resumen = {
        "ventas_dia": ingresos,
        "vendido_dia": vendido,
        "tickets": tickets,
        "pedidos_abiertos": pedidos_abiertos["pedidos"] or 0,
        "pedidos_totales": tickets + (pedidos_abiertos["pedidos"] or 0),
        "ticket_promedio": ticket_promedio,
        "piezas_activas": piezas_abiertas or 0,
        "piezas_nuevas_10": piezas_nuevas_10 or 0,
        "estado_operacion": carga_negocio["label"],
        "estado_operacion_id": carga_negocio["id"],
        "mensaje_operacion": carga_negocio["mensaje"],
        "producto_mas_vendido": producto_mas_vendido["producto"] if producto_mas_vendido else "Sin ventas",
        "producto_mas_vendido_cantidad": producto_mas_vendido["vendidos"] if producto_mas_vendido else 0,
        "producto_mayor_ingreso": producto_mayor_ingreso["producto"] if producto_mayor_ingreso else "Sin ventas",
        "producto_mayor_ingreso_total": producto_mayor_ingreso["ingresos"] if producto_mayor_ingreso else 0,
        "producto_mas_lento": producto_mas_lento["producto"] if producto_mas_lento and producto_mas_lento["tiempo_promedio"] else "Sin datos",
        "producto_mas_lento_tiempo": producto_mas_lento["tiempo_promedio"] if producto_mas_lento else 0,
    }

    decisiones = []
    if (pedidos_abiertos["pedidos"] or 0) >= 10 or (piezas_abiertas or 0) >= 30:
        decisiones.append({
            "prioridad": "alta",
            "etiqueta": "Produccion",
            "orden": "Reforzar produccion",
            "titulo": "Carga alta en produccion",
            "texto": "Hay carga activa alta. Conviene ajustar tiempos y apoyar la estacion con mas trabajo.",
            "accion": "Asignar apoyo y avisar 15 min extra.",
        })

    if producto_mas_lento and producto_mas_lento["tiempo_promedio"]:
        decisiones.append({
            "prioridad": "media",
            "etiqueta": "Menu",
            "orden": "Revisar producto lento",
            "titulo": "Producto lento",
            "texto": f"{producto_mas_lento['producto']} tarda {producto_mas_lento['tiempo_promedio']} min en promedio.",
            "accion": "Revisar precio, preparacion previa o limite en hora pico.",
        })

    if producto_mas_vendido:
        decisiones.append({
            "prioridad": "oportunidad",
            "etiqueta": "Crecimiento",
            "orden": "Promover producto fuerte",
            "titulo": "Producto fuerte",
            "texto": f"{producto_mas_vendido['producto']} es el mas vendido con {producto_mas_vendido['vendidos']} piezas.",
            "accion": "Promoverlo y mantenerlo rapido.",
        })

    if tickets and ticket_promedio < 150:
        decisiones.append({
            "prioridad": "media",
            "etiqueta": "Venta",
            "orden": "Crear combo",
            "titulo": "Ticket promedio bajo",
            "texto": "El ticket promedio puede subir con combos, bebidas o extras simples.",
            "accion": "Sugerir bebida o extra en caja.",
        })
    elif tickets:
        decisiones.append({
            "prioridad": "normal",
            "etiqueta": "Venta",
            "orden": "Cuidar ticket promedio",
            "titulo": "Ticket promedio",
            "texto": f"El ticket promedio esta en ${ticket_promedio}.",
            "accion": "Compararlo contra tu meta diaria.",
        })

    if not decisiones:
        decisiones.append({
            "prioridad": "normal",
            "etiqueta": "Inicio",
            "orden": "Capturar ventas",
            "titulo": "Sin datos suficientes",
            "texto": "Cuando cierres ventas, aqui apareceran recomendaciones de menu y operacion.",
            "accion": "Capturar ventas reales para alimentar decisiones.",
        })

    decision_principal = decisiones[0]
    oportunidad = next(
        (decision for decision in decisiones if decision["prioridad"] == "oportunidad"),
        decisiones[-1],
    )

    conn.close()
    return {
        "fecha": fecha,
        "resumen": resumen,
        "productos_menu": productos_menu,
        "decisiones": decisiones,
        "decision_principal": decision_principal,
        "oportunidad": oportunidad,
        "red_local": f"http://{obtener_ip_local()}:5001",
    }


def obtener_historial_produccion(fecha=None):
    conn = conectar_db()
    fecha = fecha or datetime.now().strftime("%Y-%m-%d")
    filtro = fecha + "%"
    etapas_produccion = [etapa for etapa in ETAPAS if etapa != "listo"]
    limite_10_min = datetime.now() - timedelta(minutes=10)

    historial = conn.execute("""
        SELECT *
        FROM etapa_historial
        WHERE fecha_entrada LIKE ?
           OR COALESCE(fecha_salida, '') LIKE ?
        ORDER BY id DESC
        LIMIT 120
    """, (filtro, filtro)).fetchall()

    promedios_db = conn.execute("""
        SELECT etapa,
               COUNT(*) AS registros,
               ROUND(AVG(duracion_minutos), 2) AS promedio
        FROM etapa_historial
        WHERE fecha_salida LIKE ?
          AND duracion_minutos IS NOT NULL
        GROUP BY etapa
    """, (filtro,)).fetchall()

    promedios = {
        etapa: {"registros": 0, "promedio": 0, "nombre": etapa_nombre(etapa)}
        for etapa in etapas_produccion
    }
    for fila in promedios_db:
        promedio = fila["promedio"] or 0
        promedios[fila["etapa"]] = {
            "registros": fila["registros"],
            "promedio": promedio,
            "nombre": etapa_nombre(fila["etapa"]),
        }

    abiertos_db = conn.execute("""
        SELECT *
        FROM etapa_historial
        WHERE fecha_salida IS NULL
        ORDER BY fecha_entrada ASC
    """).fetchall()

    abiertos = []
    for fila in abiertos_db:
        item = dict(fila)
        minutos = minutos_abierto(item["fecha_entrada"])
        item["minutos_abierto"] = minutos
        item["tiempo_abierto"] = texto_tiempo(minutos)
        item["estado_carga"] = "normal"
        abiertos.append(item)

    total_cerrados = sum(datos["registros"] for datos in promedios.values())

    carga_estaciones = []
    for etapa in etapas_produccion:
        abiertos_etapa = [item for item in abiertos if item["etapa"] == etapa]
        piezas_activas = sum(item["cantidad"] for item in abiertos_etapa)
        pedidos_activos = len({item["folio"] for item in abiertos_etapa})
        piezas_nuevas_10 = 0

        for item in abiertos_etapa:
            try:
                entrada = datetime.strptime(item["fecha_entrada"], "%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError):
                entrada = datetime.now()

            if entrada >= limite_10_min:
                piezas_nuevas_10 += item["cantidad"]

        carga = estado_carga(piezas_activas, piezas_nuevas_10)
        carga_estaciones.append({
            "id": etapa,
            "nombre": etapa_nombre(etapa),
            "piezas_activas": piezas_activas,
            "piezas_nuevas_10": piezas_nuevas_10,
            "pedidos_activos": pedidos_activos,
            "promedio": promedios[etapa]["promedio"],
            "estado_id": carga["id"],
            "estado": carga["label"],
            "mensaje": carga["mensaje"],
            "score": piezas_activas + (piezas_nuevas_10 * 1.5),
        })

    demanda_estaciones = [item for item in carga_estaciones if item["estado_id"] != "normal"]

    completados = conn.execute("""
        SELECT
            etapa_historial.linea_id,
            etapa_historial.folio,
            etapa_historial.cliente,
            etapa_historial.producto,
            MAX(etapa_historial.cantidad) AS cantidad,
            ROUND(SUM(etapa_historial.duracion_minutos), 2) AS tiempo_total,
            COUNT(*) AS etapas,
            MAX(etapa_historial.fecha_salida) AS fecha_fin
        FROM etapa_historial
        WHERE etapa_historial.linea_id IN (
            SELECT DISTINCT linea_id
            FROM etapa_historial
            WHERE fecha_salida LIKE ?
        )
          AND etapa_historial.duracion_minutos IS NOT NULL
          AND NOT EXISTS (
              SELECT 1
              FROM etapa_historial abiertos
              WHERE abiertos.linea_id = etapa_historial.linea_id
                AND abiertos.fecha_salida IS NULL
          )
        GROUP BY etapa_historial.linea_id, etapa_historial.folio,
                 etapa_historial.cliente, etapa_historial.producto
        ORDER BY fecha_fin DESC
        LIMIT 40
    """, (filtro,)).fetchall()

    productividad = conn.execute("""
        SELECT
            COALESCE(NULLIF(usuario_salida, ''), 'Sistema') AS usuario,
            COALESCE(NULLIF(rol_salida, ''), 'sistema') AS rol,
            etapa,
            COUNT(*) AS completadas,
            ROUND(AVG(duracion_minutos), 2) AS promedio
        FROM etapa_historial
        WHERE fecha_salida LIKE ?
          AND duracion_minutos IS NOT NULL
        GROUP BY usuario, rol, etapa
        ORDER BY completadas DESC, promedio ASC
    """, (filtro,)).fetchall()

    productos_lentos = conn.execute("""
        SELECT
            producto,
            COUNT(*) AS productos,
            ROUND(AVG(tiempo_total), 2) AS promedio_total
        FROM (
            SELECT
                linea_id,
                producto,
                SUM(duracion_minutos) AS tiempo_total
            FROM etapa_historial
            WHERE linea_id IN (
                SELECT DISTINCT linea_id
                FROM etapa_historial
                WHERE fecha_salida LIKE ?
            )
              AND duracion_minutos IS NOT NULL
            GROUP BY linea_id, producto
        )
        GROUP BY producto
        HAVING productos > 0
        ORDER BY promedio_total DESC
        LIMIT 8
    """, (filtro,)).fetchall()

    tiempos_totales = [fila["tiempo_total"] or 0 for fila in completados]
    promedio_total = round(sum(tiempos_totales) / len(tiempos_totales), 2) if tiempos_totales else 0
    mayor_carga = max(
        carga_estaciones,
        key=lambda item: item["score"],
        default=None,
    )
    piezas_activas_total = sum(item["piezas_activas"] for item in carga_estaciones)
    piezas_nuevas_10_total = sum(item["piezas_nuevas_10"] for item in carga_estaciones)
    pedidos_pendientes = conn.execute("SELECT COUNT(*) AS total FROM pedidos").fetchone()["total"]
    carga_general = estado_carga(
        piezas_activas_total,
        piezas_nuevas_10_total,
        alta_activos=25,
        saturado_activos=45,
        alta_nuevos=15,
        saturado_nuevos=25,
    )

    resumen = {
        "pedidos_activos": len({item["folio"] for item in abiertos}),
        "pedidos_pendientes": pedidos_pendientes,
        "productos_activos": len(abiertos),
        "piezas_activas": piezas_activas_total,
        "nuevos_10_min": piezas_nuevas_10_total,
        "estado_carga": carga_general["label"],
        "estado_carga_id": carga_general["id"],
        "mensaje_carga": carga_general["mensaje"],
        "promedio_total": promedio_total,
        "lineas_completadas": len(completados),
        "mayor_carga": mayor_carga["nombre"] if mayor_carga else "Sin datos",
        "mayor_carga_piezas": mayor_carga["piezas_activas"] if mayor_carga else 0,
        "mayor_carga_nuevos": mayor_carga["piezas_nuevas_10"] if mayor_carga else 0,
        "mayor_carga_estado": mayor_carga["estado"] if mayor_carga else "Carga normal",
        "mayor_carga_estado_id": mayor_carga["estado_id"] if mayor_carga else "normal",
    }

    conn.close()
    return {
        "historial": historial,
        "promedios": promedios,
        "carga_estaciones": carga_estaciones,
        "demanda_estaciones": demanda_estaciones,
        "abiertos": abiertos,
        "completados": completados,
        "productividad": productividad,
        "productos_lentos": productos_lentos,
        "total_cerrados": total_cerrados,
        "resumen": resumen,
        "fecha": fecha,
    }


def destino_por_rol():
    rol = session.get("rol")
    if rol == "cocina":
        return url_for("cocina")
    if rol == "empanizado":
        return url_for("empanizado")
    if rol == "decoracion":
        return url_for("decoracion")
    return url_for("index")


def nav_items():
    rol = session.get("rol")
    items = []

    if rol in ("caja", "administrador"):
        items.append({"vista": "caja", "label": "Caja", "url": url_for("index")})
    if rol in ("cocina", "administrador"):
        items.append({"vista": "cocina", "label": "Armado", "url": url_for("cocina")})
    if rol in ("empanizado", "administrador"):
        items.append({"vista": "empanizado", "label": "Empanizado", "url": url_for("empanizado")})
    if rol in ("decoracion", "administrador"):
        items.append({"vista": "decoracion", "label": "Decoracion", "url": url_for("decoracion")})
    if rol in ("caja", "administrador"):
        items.append({"vista": "ventas", "label": "Ventas", "url": url_for("ventas_historial")})
    if rol == "administrador":
        items.append({"vista": "negocio", "label": "Resumen", "url": url_for("negocio")})
        items.append({"vista": "produccion", "label": "Produccion", "url": url_for("produccion")})
        items.append({"vista": "inventario", "label": "Inventario", "url": url_for("inventario")})

    return items


@app.before_request
def respaldo_diario_automatico():
    asegurar_respaldo_diario()


@app.before_request
def proteger_formularios():
    if request.method == "POST":
        validar_csrf()


@app.after_request
def headers_seguridad(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


def requiere_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login", next=request.path))
        return func(*args, **kwargs)
    return wrapper


def requiere_roles(*roles):
    def decorador(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "usuario" not in session:
                return redirect(url_for("login", next=request.path))
            if session.get("rol") not in roles:
                flash("Tu usuario no tiene permiso para esa pantalla.", "error")
                return redirect(destino_por_rol())
            return func(*args, **kwargs)
        return wrapper
    return decorador


def contexto_base():
    return {
        "menu": MENU,
        "metodos_pago": METODOS_PAGO,
        "metodo_nombre": metodo_nombre,
        "preparaciones": PREPARACIONES,
        "quitar_opciones": QUITAR_OPCIONES,
        "terminado_opciones": TERMINADO_OPCIONES,
        "por_dentro_opciones": POR_DENTRO_OPCIONES,
        "etapa_nombre": etapa_nombre,
        "usuario": session.get("usuario"),
        "rol": session.get("rol"),
        "nav_items": nav_items() if session.get("usuario") else [],
        "csrf_token": obtener_csrf_token(),
        "mostrar_credenciales_demo": os.environ.get("SHOW_DEMO_ACCESS", "0") == "1",
    }


def render_fragment(contenido_template, **contexto):
    return agregar_csrf_a_forms(render_template_string(contenido_template, **contexto))


def render_page(titulo, vista, contenido_template, **contexto):
    contexto_base_render = contexto_base()
    contexto_base_render.update(contexto)

    contenido = render_template_string(contenido_template, **contexto_base_render)

    html = render_template_string(
        BASE_HTML,
        titulo=titulo,
        vista=vista,
        contenido=contenido,
        **contexto_base_render,
    )
    return agregar_csrf_a_forms(html)


def quiere_json():
    return (
        request.headers.get("X-Requested-With") == "fetch"
        or "application/json" in request.headers.get("Accept", "")
    )


def contexto_caja(pedido_activo_id=None):
    pedidos = obtener_pedidos()
    pedidos_ids = {pedido["id"] for pedido in pedidos}

    if pedido_activo_id is None:
        pedido_activo_id = session.get("pedido_activo_id")

    if pedido_activo_id in pedidos_ids:
        session["pedido_activo_id"] = pedido_activo_id
    else:
        session.pop("pedido_activo_id", None)
        pedido_activo_id = None

    pedido_activo = next((pedido for pedido in pedidos if pedido["id"] == pedido_activo_id), None)
    ventas_dia, total_ventas, total_ingresos, totales_metodo, fecha_hoy = obtener_ventas()

    contexto = contexto_base()
    contexto.update({
        "menu_categorias": menu_por_categoria(),
        "pedidos": pedidos,
        "pedido_activo_id": pedido_activo_id,
        "pedido_activo": pedido_activo,
        "ventas": ventas_dia,
        "total_ventas": total_ventas,
        "total_ingresos": total_ingresos,
        "totales_metodo": totales_metodo,
        "fecha_hoy": fecha_hoy,
        "conteo": contar_por_estado(pedidos),
    })
    return contexto


def respuesta_caja_ajax(pedido_activo_id=None, mensaje="", categoria="success", status=200):
    contexto = contexto_caja(pedido_activo_id)
    return jsonify({
        "ok": categoria != "error",
        "message": mensaje,
        "category": categoria,
        "pedido_activo_id": contexto["pedido_activo_id"],
        "fragments": {
            "metrics": render_fragment(HTML_CAJA_METRICS_INNER, **contexto),
            "active_order": render_fragment(HTML_PEDIDO_ACTIVO_INNER, **contexto),
            "order_select": render_fragment(HTML_PEDIDO_SELECT_OPTIONS, **contexto),
            "orders": render_fragment(HTML_PEDIDOS_ABIERTOS_INNER, **contexto),
        },
    }), status


BASE_HTML = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ titulo }}</title>

    <style>
        :root {
            --fondo: #f1efe9;
            --tarjeta: #ffffff;
            --texto: #141414;
            --gris: #5e5b55;
            --linea: #d4cec3;
            --negro: #0a0a0a;
            --dorado: #b08a44;
            --rojo: #8c2f2f;
            --verde: #2f6f4f;
            --azul: #3a4f6a;
            --amarillo: #8a6225;
            --sombra: 0 6px 18px rgba(0, 0, 0, 0.05);
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: var(--fondo);
            color: var(--texto);
            font-family: "Inter", "Segoe UI", Arial, sans-serif;
        }

        a {
            color: inherit;
        }

        h1, h2, h3, p {
            margin-top: 0;
        }

        h1 {
            margin-bottom: 6px;
            font-size: 30px;
            line-height: 1.12;
            font-weight: 800;
        }

        h2 {
            margin-bottom: 14px;
            font-size: 19px;
            font-weight: 800;
        }

        h3 {
            margin-bottom: 8px;
            font-size: 17px;
        }

        .muted {
            color: var(--gris);
        }

        .topbar {
            position: sticky;
            top: 0;
            z-index: 10;
            background: #ffffff;
            border-bottom: 1px solid #ddd;
            backdrop-filter: none;
        }

        .topbar-inner {
            max-width: 1320px;
            margin: 0 auto;
            padding: 12px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            min-width: 220px;
            font-weight: 800;
        }

        .brand-logo {
            width: 54px;
            height: 54px;
            border-radius: 8px;
            overflow: hidden;
            background: var(--negro);
            border: 1px solid #1f1f1f;
            flex: 0 0 auto;
        }

        .brand-logo img {
            width: 100%;
            height: 100%;
            object-fit: contain;
            display: block;
        }

        .brand small {
            display: block;
            margin-top: 2px;
            color: var(--gris);
            font-weight: 600;
        }

        .nav {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 8px;
            flex-wrap: wrap;
        }

        .nav a,
        .nav button,
        .button {
            min-height: 42px;
            border: 1px solid var(--linea);
            background: var(--tarjeta);
            color: var(--texto);
            border-radius: 6px;
            padding: 10px 15px;
            text-decoration: none;
            font-weight: 750;
            font-size: 14px;
            cursor: pointer;
        }

        .nav a.active {
            border-color: var(--negro);
            background: var(--negro);
            color: white;
        }

        .nav form {
            margin: 0;
        }

        .page {
            max-width: 1320px;
            margin: 0 auto;
            padding: 22px 20px 48px;
        }

        .page-head {
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 18px;
        }

        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }

        .metric,
        .panel,
        .order-card,
        .ticket,
        .login-card {
            border: 1px solid var(--linea);
            border-radius: 4px;
            background: var(--tarjeta);
            box-shadow: none;
        }

        .metric {
            padding: 16px;
        }

        .metric span {
            display: block;
            color: var(--gris);
            font-size: 12px;
            font-weight: 800;
            letter-spacing: 0;
            text-transform: uppercase;
        }

        .metric strong {
            display: block;
            margin-top: 8px;
            font-size: 28px;
        }

        .workspace {
            display: grid;
            grid-template-columns: 390px minmax(0, 1fr);
            gap: 18px;
            align-items: start;
        }

        .panel {
            padding: 18px;
        }

        .sticky-panel {
            position: sticky;
            top: 92px;
        }

        .field-grid {
            display: grid;
            gap: 12px;
        }

        label {
            display: block;
            margin-bottom: 7px;
            font-weight: 800;
        }

        input,
        select,
        textarea {
            width: 100%;
            min-height: 44px;
            border: 1px solid var(--linea);
            border-radius: 6px;
            padding: 11px 12px;
            background: white;
            color: var(--texto);
            font: inherit;
        }

        textarea {
            min-height: 82px;
            resize: vertical;
        }

        .option-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 8px;
        }

        .checkbox-pill {
            min-height: 42px;
            display: flex;
            align-items: center;
            gap: 8px;
            border: 1px solid var(--linea);
            border-radius: 6px;
            background: white;
            padding: 9px 10px;
            font-weight: 750;
            cursor: pointer;
        }

        .checkbox-pill input {
            width: auto;
            min-height: 0;
        }

        .category {
            margin-top: 18px;
        }

        .category-title {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--linea);
            font-weight: 900;
        }

        .menu-grid {
            display: grid;
            gap: 10px;
        }

        .menu-item {
            width: 100%;
            min-height: 76px;
            border: 1px solid var(--linea);
            border-radius: 6px;
            padding: 14px;
            background: white;
            cursor: pointer;
            text-align: left;
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            align-items: center;
            gap: 14px;
        }

        .menu-item:hover,
        .menu-item:focus {
            border-color: var(--dorado);
            background: #fffdf8;
            outline: none;
        }

        .menu-item strong,
        .menu-item small {
            display: block;
        }

        .menu-item small {
            margin-top: 3px;
            color: var(--gris);
            font-weight: 800;
        }

        .price {
            color: #7a5a13;
            font-weight: 900;
            white-space: nowrap;
        }

        .orders {
            display: grid;
            gap: 14px;
        }

        .order-card {
            padding: 16px;
            border-left: 6px solid var(--amarillo);
        }

        .order-card.activo {
            border-color: var(--dorado);
            border-left-color: var(--dorado);
            box-shadow: none;
        }

        .order-card.listo {
            border-left-color: var(--verde);
        }

        .order-card.decoracion {
            border-left-color: var(--azul);
        }

        .order-card.empanizado {
            border-left-color: var(--rojo);
        }

        .order-card.alerta {
            border-left-color: var(--amarillo);
            background: #fffdf7;
        }

        .active-strip {
            display: grid;
            gap: 8px;
            margin: 12px 0;
            padding: 12px;
            border: 1px solid var(--dorado);
            border-radius: 8px;
            background: #faf8f2;
            font-weight: 900;
        }

        .quick-title {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            margin-bottom: 8px;
        }

        .order-head {
            display: flex;
            justify-content: space-between;
            gap: 14px;
            align-items: flex-start;
            margin-bottom: 12px;
        }

        .order-title {
            margin: 0 0 4px;
            font-size: 21px;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            padding: 7px 10px;
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
            white-space: nowrap;
        }

        .badge.pendiente {
            background: #fff4d6;
            color: var(--amarillo);
        }

        .badge.armado {
            background: #fff4d6;
            color: var(--amarillo);
        }

        .badge.decoracion {
            background: #f4f4f2;
            color: var(--azul);
        }

        .badge.empanizado {
            background: #f5eeee;
            color: var(--rojo);
        }

        .badge.listo {
            background: #eef3ef;
            color: var(--verde);
        }

        .products {
            margin: 0;
            padding: 0;
            list-style: none;
            border-top: 1px solid var(--linea);
            border-bottom: 1px solid var(--linea);
        }

        .products li {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto auto;
            align-items: center;
            gap: 12px;
            padding: 11px 0;
        }

        .line-main strong,
        .line-main span {
            display: block;
        }

        .line-main span {
            margin-top: 2px;
            color: var(--gris);
            font-size: 13px;
            font-weight: 700;
        }

        .line-details {
            grid-column: 1 / -1;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            color: var(--gris);
            font-size: 13px;
            font-weight: 800;
        }

        .detail-chip,
        .stage-chip {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            padding: 5px 9px;
            background: #f4f4f2;
            color: var(--azul);
            font-size: 12px;
            font-weight: 900;
        }

        .stage-chip.armado_pendiente {
            background: #fff4d6;
            color: var(--amarillo);
        }

        .stage-chip.decoracion_pendiente {
            background: #f4f4f2;
            color: var(--azul);
        }

        .stage-chip.empanizado_pendiente {
            background: #f5eeee;
            color: var(--rojo);
        }

        .stage-chip.listo {
            background: #eef3ef;
            color: var(--verde);
        }

        .line-actions,
        .actions,
        .pay-form,
        .filters,
        .screen-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .line-actions form,
        .actions form {
            margin: 0;
        }

        .qty-button {
            width: 38px;
            min-height: 38px;
            border: 1px solid var(--linea);
            border-radius: 6px;
            background: white;
            font-size: 18px;
            font-weight: 800;
            cursor: pointer;
        }

        .button.primary {
            background: #111;
            border: 1px solid #111;
            color: #fff;
            letter-spacing: 0.3px;
        }

        .button.ready {
            border-color: var(--verde);
            background: var(--verde);
            color: white;
        }

        .button.danger {
            border-color: #8f3b32;
            background: #8f3b32;
            color: white;
        }

        .button.ghost {
            background: transparent;
        }

        .button.compact {
            min-height: 36px;
            padding: 8px 10px;
        }

        .button.busy,
        .menu-item.busy {
            opacity: 0.62;
            pointer-events: none;
        }

        .button.same {
            border-color: var(--dorado);
            background: #faf8f2;
            color: #5f4617;
        }

        .order-foot {
            display: grid;
            grid-template-columns: auto minmax(260px, 1fr);
            align-items: center;
            gap: 12px;
            margin-top: 14px;
        }

        .order-total {
            font-size: 18px;
            font-weight: 900;
        }

        .pay-form {
            justify-content: flex-end;
        }

        .pay-form select {
            max-width: 180px;
        }

        .work-list {
            display: grid;
            gap: 12px;
            margin: 0;
            padding: 0;
            list-style: none;
            border-top: 1px solid var(--linea);
        }

        .work-item {
            display: grid;
            gap: 10px;
            padding: 14px 0;
            border-bottom: 1px solid var(--linea);
        }

        .work-meta {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 8px;
        }

        .work-box {
            border: 1px solid var(--linea);
            border-radius: 8px;
            background: #fbfcff;
            padding: 10px;
        }

        .work-box span {
            display: block;
            color: var(--gris);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
            margin-bottom: 4px;
        }

        .timer {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            padding: 6px 10px;
            background: #f4f4f2;
            color: var(--azul);
            font-size: 12px;
            font-weight: 900;
        }

        .timer.amarilla {
            background: #fff0d7;
            color: var(--amarillo);
        }

        .timer.roja {
            background: #f5eeee;
            color: var(--rojo);
        }

        .load-chip {
            display: inline-flex;
            justify-content: center;
            align-items: center;
            min-height: 34px;
            border-radius: 999px;
            padding: 7px 11px;
            background: #eef3ef;
            color: var(--verde);
            font-size: 12px;
            font-weight: 900;
            white-space: nowrap;
        }

        .load-chip.alta {
            background: #fff0d7;
            color: var(--amarillo);
        }

        .load-chip.saturado {
            background: #f5eeee;
            color: var(--rojo);
        }

        .empty {
            border: 1px dashed var(--linea);
            border-radius: 8px;
            padding: 28px;
            background: white;
            text-align: center;
            color: var(--gris);
        }

        .flash-list {
            display: grid;
            gap: 8px;
            margin-bottom: 16px;
        }

        .flash {
            border-radius: 8px;
            padding: 12px 14px;
            font-weight: 800;
        }

        .flash.success {
            background: #eef3ef;
            color: var(--verde);
        }

        .flash.error {
            background: #f5eeee;
            color: var(--rojo);
        }

        .flash.info {
            background: #f4f4f2;
            color: var(--azul);
        }

        .ajax-toast {
            position: fixed;
            right: 18px;
            bottom: 18px;
            z-index: 50;
            max-width: min(360px, calc(100vw - 36px));
            border-radius: 8px;
            padding: 12px 14px;
            background: var(--negro);
            color: white;
            font-weight: 900;
            box-shadow: none;
            transform: translateY(16px);
            opacity: 0;
            transition: opacity 160ms ease, transform 160ms ease;
        }

        .ajax-toast.show {
            transform: translateY(0);
            opacity: 1;
        }

        .ajax-toast.error {
            background: var(--rojo);
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
        }

        .data-table th,
        .data-table td {
            padding: 12px 10px;
            border-bottom: 1px solid var(--linea);
            text-align: left;
            vertical-align: middle;
        }

        .data-table th {
            color: var(--gris);
            font-size: 12px;
            text-transform: uppercase;
        }

        .production-overview {
            display: grid;
            grid-template-columns: minmax(0, 1.5fr) minmax(280px, 0.85fr);
            gap: 18px;
            align-items: stretch;
            margin-bottom: 18px;
        }

        .stage-list {
            display: grid;
            gap: 14px;
        }

        .stage-row {
            display: grid;
            grid-template-columns: 135px minmax(0, 1fr) 140px;
            gap: 12px;
            align-items: center;
        }

        .stage-row small {
            grid-column: 2 / -1;
        }

        .stage-bar {
            overflow: hidden;
            height: 14px;
            border-radius: 999px;
            background: #edf1f7;
        }

        .stage-fill {
            width: min(calc(var(--value) * 6%), 100%);
            height: 100%;
            border-radius: inherit;
            background: var(--verde);
        }

        .stage-row.alta .stage-fill,
        .stage-row.amarilla .stage-fill {
            background: var(--amarillo);
        }

        .stage-row.saturado .stage-fill,
        .stage-row.roja .stage-fill {
            background: var(--rojo);
        }

        .bottleneck {
            display: grid;
            gap: 10px;
            align-content: center;
            border-left: 5px solid var(--verde);
        }

        .bottleneck.alta,
        .bottleneck.amarilla {
            border-left-color: var(--amarillo);
            background: #fffaf0;
        }

        .bottleneck.saturado,
        .bottleneck.roja {
            border-left-color: var(--rojo);
            background: #f5eeee;
        }

        .bottleneck strong {
            display: block;
            font-size: 30px;
        }

        .status-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
            margin-top: 12px;
        }

        .status-box {
            border: 1px solid var(--linea);
            border-radius: 8px;
            padding: 12px;
            background: #fbfcff;
        }

        .status-box span {
            display: block;
            color: var(--gris);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .status-box strong {
            display: block;
            margin-top: 6px;
            font-size: 24px;
        }

        .business-stack {
            display: grid;
            gap: 18px;
        }

        .owner-command {
            display: grid;
            grid-template-columns: minmax(0, 1.4fr) minmax(260px, 0.7fr);
            gap: 18px;
            align-items: stretch;
            border: 1px solid var(--dorado);
            background: #fffaf0;
            margin-bottom: 18px;
        }

        .owner-command.alta {
            border-color: var(--rojo);
            background: #f5eeee;
        }

        .owner-command.media {
            border-color: var(--amarillo);
            background: #fffaf0;
        }

        .owner-command.oportunidad {
            border-color: var(--azul);
            background: #f4f4f2;
        }

        .owner-label {
            display: inline-flex;
            width: fit-content;
            border-radius: 999px;
            padding: 7px 11px;
            background: var(--negro);
            color: white;
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .owner-command h2 {
            margin: 12px 0 10px;
            font-size: 36px;
            line-height: 1.04;
        }

        .owner-action {
            border-radius: 8px;
            padding: 13px;
            background: white;
            border: 1px solid var(--linea);
            font-weight: 900;
        }

        .owner-side {
            display: grid;
            gap: 12px;
        }

        .owner-side .status-box {
            background: white;
        }

        .business-section {
            display: grid;
            gap: 14px;
        }

        .business-section h2 {
            margin-bottom: 0;
        }

        .business-cards {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
        }

        .business-card {
            border: 1px solid var(--linea);
            border-radius: 8px;
            background: #fbfcff;
            padding: 16px;
            min-height: 118px;
        }

        .business-card span {
            display: block;
            color: var(--gris);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .business-card strong {
            display: block;
            margin-top: 8px;
            font-size: 28px;
            line-height: 1.05;
        }

        .business-card small {
            display: block;
            margin-top: 8px;
            color: var(--gris);
            font-weight: 800;
        }

        .control-center {
            display: grid;
            gap: 18px;
        }

        .control-hero {
            display: grid;
            grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.65fr);
            gap: 18px;
            align-items: stretch;
            border: 1px solid var(--dorado);
            background: linear-gradient(135deg, #fffaf0 0%, white 70%);
            margin-bottom: 18px;
        }

        .control-hero.alta {
            border-color: var(--rojo);
            background: #fff;
        }

        .control-hero.media {
            border-color: var(--amarillo);
            background: linear-gradient(135deg, #fff4d6 0%, white 68%);
        }

        .control-hero.oportunidad {
            border-color: var(--azul);
            background: #fff;
        }

        .control-hero.normal {
            border-color: var(--verde);
            background: #fff;
        }

        .control-label {
            display: inline-flex;
            width: fit-content;
            border-radius: 999px;
            padding: 8px 12px;
            background: var(--negro);
            color: white;
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .control-hero h2 {
            margin: 14px 0 10px;
            max-width: 780px;
            font-size: 42px;
            line-height: 1.02;
        }

        .control-copy {
            max-width: 760px;
            font-size: 18px;
        }

        .control-action {
            display: grid;
            gap: 6px;
            margin-top: 18px;
            border-radius: 8px;
            padding: 16px;
            background: white;
            border: 1px solid var(--linea);
            box-shadow: none;
        }

        .control-action span {
            color: var(--gris);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .control-action strong {
            font-size: 20px;
            line-height: 1.2;
        }

        .operation-state {
            display: grid;
            gap: 12px;
            align-content: center;
            border: 1px solid var(--linea);
            border-radius: 8px;
            padding: 18px;
            background: white;
        }

        .operation-state span {
            color: var(--gris);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .operation-state strong {
            font-size: 34px;
            line-height: 1;
        }

        .operation-state small {
            color: var(--gris);
            font-weight: 800;
            line-height: 1.35;
        }

        .operation-state.normal {
            border-color: var(--verde);
            background: #eef3ef;
            color: var(--verde);
        }

        .operation-state.alta {
            border-color: var(--amarillo);
            background: #fff4d6;
            color: var(--amarillo);
        }

        .operation-state.saturado {
            border-color: var(--rojo);
            background: #f5eeee;
            color: var(--rojo);
        }

        .command-grid,
        .product-focus-grid,
        .operation-grid {
            display: grid;
            gap: 12px;
        }

        .command-grid {
            grid-template-columns: repeat(4, minmax(0, 1fr));
        }

        .product-focus-grid {
            grid-template-columns: repeat(3, minmax(0, 1fr));
        }

        .operation-grid {
            grid-template-columns: minmax(0, 0.75fr) repeat(2, minmax(0, 1fr));
            align-items: stretch;
        }

        .command-card,
        .product-focus-card,
        .operation-card {
            border: 1px solid var(--linea);
            border-radius: 8px;
            background: #fbfcff;
            padding: 18px;
            min-height: 124px;
        }

        .command-card span,
        .product-focus-card span,
        .operation-card span {
            display: block;
            color: var(--gris);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .command-card strong,
        .product-focus-card strong,
        .operation-card strong {
            display: block;
            margin-top: 9px;
            font-size: 32px;
            line-height: 1.05;
        }

        .command-card small,
        .product-focus-card small,
        .operation-card small {
            display: block;
            margin-top: 9px;
            color: var(--gris);
            font-weight: 800;
        }

        .command-card.money {
            border-left: 6px solid var(--verde);
        }

        .command-card.ticket {
            border-left: 6px solid var(--azul);
        }

        .command-card.active {
            border-left: 6px solid var(--amarillo);
        }

        .product-focus-card.fast {
            border-left: 6px solid var(--verde);
        }

        .product-focus-card.cash {
            border-left: 5px solid var(--dorado);
        }

        .product-focus-card.slow {
            border-left: 6px solid var(--rojo);
        }

        .section-title-row {
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            gap: 12px;
            margin-bottom: 14px;
        }

        .section-title-row h2 {
            margin-bottom: 0;
        }

        .section-title-row p {
            margin-bottom: 0;
        }

        .decision-list strong {
            display: block;
            margin-top: 7px;
            font-size: 18px;
        }

        .business-console {
            display: grid;
            gap: 18px;
        }

        .console-hero {
            position: relative;
            overflow: hidden;
            display: grid;
            grid-template-columns: minmax(0, 1.35fr) minmax(300px, 0.65fr);
            gap: 18px;
            align-items: stretch;
            border: 0;
            background: #0c0d10;
            color: white;
            box-shadow: none;
        }

        .console-hero::before {
            content: "";
            position: absolute;
            inset: 0;
            border-left: 6px solid var(--dorado);
            pointer-events: none;
        }

        .console-hero.alta::before {
            border-left-color: var(--rojo);
        }

        .console-hero.media::before {
            border-left-color: var(--amarillo);
        }

        .console-hero.oportunidad::before {
            border-left-color: var(--azul);
        }

        .console-hero.normal::before {
            border-left-color: var(--verde);
        }

        .console-copy,
        .console-panel {
            position: relative;
            z-index: 1;
        }

        .console-kicker {
            display: inline-flex;
            width: fit-content;
            border-radius: 999px;
            padding: 8px 12px;
            background: rgba(255, 255, 255, 0.1);
            color: #f6d985;
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .console-command {
            display: block;
            max-width: 920px;
            margin-top: 18px;
            color: white;
            font-size: 64px;
            font-weight: 900;
            line-height: 0.94;
            text-transform: uppercase;
        }

        .console-hero h2 {
            max-width: 820px;
            margin: 14px 0 10px;
            color: rgba(255, 255, 255, 0.9);
            font-size: 28px;
            line-height: 1.08;
        }

        .console-hero p {
            max-width: 760px;
            color: rgba(255, 255, 255, 0.78);
            font-size: 19px;
            line-height: 1.45;
        }

        .console-action {
            display: grid;
            gap: 7px;
            margin-top: 20px;
            border-radius: 8px;
            padding: 20px;
            background: #fff7dc;
            color: var(--negro);
            border: 2px solid #f6d985;
        }

        .console-action span {
            color: var(--rojo);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .console-action strong {
            font-size: 25px;
            line-height: 1.16;
        }

        .console-panel {
            display: grid;
            gap: 12px;
        }

        .state-card {
            display: grid;
            gap: 12px;
            border-radius: 8px;
            padding: 18px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.14);
        }

        .state-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .state-top span,
        .mini-stat span {
            color: rgba(255, 255, 255, 0.72);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .state-light {
            width: 18px;
            height: 18px;
            flex: 0 0 auto;
            border-radius: 999px;
            background: var(--verde);
            box-shadow: none;
        }

        .state-card.alta .state-light {
            background: var(--amarillo);
            box-shadow: none;
        }

        .state-card.saturado .state-light {
            background: var(--rojo);
            box-shadow: none;
        }

        .state-card strong {
            display: block;
            color: white;
            font-size: 38px;
            line-height: 1;
        }

        .state-card small,
        .mini-stat small {
            color: rgba(255, 255, 255, 0.72);
            font-weight: 800;
            line-height: 1.35;
        }

        .mini-stat-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }

        .mini-stat {
            border-radius: 8px;
            padding: 14px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.12);
        }

        .mini-stat strong {
            display: block;
            margin-top: 6px;
            color: white;
            font-size: 28px;
        }

        .console-section {
            border: 0;
            background: white;
            box-shadow: none;
        }

        .console-section .section-title-row {
            margin-bottom: 16px;
        }

        .console-metrics {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }

        .console-metric,
        .console-product,
        .console-action-item {
            position: relative;
            overflow: hidden;
            border: 1px solid var(--linea);
            border-radius: 8px;
            background: #fbfcff;
            padding: 18px;
        }

        .console-metric {
            min-height: 132px;
        }

        .console-metric::before,
        .console-product::before {
            content: "";
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 6px;
            background: var(--azul);
        }

        .console-metric.money::before {
            background: var(--verde);
        }

        .console-metric.ticket::before {
            background: var(--azul);
        }

        .console-metric.active::before {
            background: var(--amarillo);
        }

        .console-metric span,
        .console-product span,
        .console-action-item span {
            display: block;
            color: var(--gris);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .console-metric strong {
            display: block;
            margin-top: 10px;
            font-size: 34px;
            line-height: 1;
        }

        .console-metric small,
        .console-product small,
        .console-action-item small {
            display: block;
            margin-top: 10px;
            color: var(--gris);
            font-weight: 800;
            line-height: 1.35;
        }

        .console-products {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
        }

        .console-product {
            min-height: 156px;
        }

        .console-product.best::before {
            background: var(--verde);
        }

        .console-product.profit::before {
            background: var(--dorado);
        }

        .console-product.slow::before {
            background: var(--rojo);
        }

        .console-product.opportunity::before {
            background: var(--azul);
        }

        .console-product strong {
            display: block;
            margin-top: 10px;
            font-size: 26px;
            line-height: 1.08;
        }

        .console-product em {
            display: inline-flex;
            width: fit-content;
            margin-top: 12px;
            border-radius: 999px;
            padding: 6px 9px;
            background: white;
            border: 1px solid var(--linea);
            color: var(--negro);
            font-style: normal;
            font-size: 12px;
            font-weight: 900;
        }

        .console-bottom {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 360px;
            gap: 18px;
            align-items: start;
        }

        .console-action-list {
            display: grid;
            gap: 12px;
            margin: 0;
            padding: 0;
            list-style: none;
        }

        .console-action-item {
            display: grid;
            gap: 7px;
            border-left: 5px solid var(--dorado);
        }

        .console-action-item.alta {
            border-left-color: var(--rojo);
            background: #f5eeee;
        }

        .console-action-item.media {
            border-left-color: var(--amarillo);
            background: #fffaf0;
        }

        .console-action-item.oportunidad {
            border-left-color: var(--azul);
            background: #f4f4f2;
        }

        .console-action-item.normal {
            border-left-color: var(--verde);
            background: #eef3ef;
        }

        .console-action-item strong {
            font-size: 20px;
        }

        .action-now {
            color: var(--negro);
            font-weight: 900;
        }

        .command-room {
            display: grid;
            gap: 20px;
        }

        .command-board {
            position: relative;
            overflow: hidden;
            display: grid;
            grid-template-columns: minmax(0, 1fr) 350px;
            gap: 20px;
            align-items: stretch;
            min-height: 340px;
            border: 1px solid #1e1c18;
            background: #11100e;
            color: white;
            box-shadow: none;
        }

        .command-board::before {
            content: "";
            position: absolute;
            inset: 0;
            border-left: 5px solid var(--dorado);
            pointer-events: none;
        }

        .command-board.alta::before {
            border-left-color: var(--rojo);
        }

        .command-board.media::before {
            border-left-color: var(--amarillo);
        }

        .command-board.oportunidad::before {
            border-left-color: var(--azul);
        }

        .command-board.normal::before {
            border-left-color: var(--verde);
        }

        .command-main,
        .command-side {
            position: relative;
            z-index: 1;
        }

        .command-main {
            display: flex;
            flex-direction: column;
            justify-content: center;
            padding-left: 6px;
        }

        .command-eyebrow {
            display: inline-flex;
            width: fit-content;
            border-radius: 6px;
            padding: 7px 10px;
            background: rgba(183, 150, 82, 0.16);
            color: #e5d1a5;
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
        }

        .main-order {
            display: block;
            max-width: 860px;
            margin-top: 16px;
            color: white;
            font-size: 52px;
            font-weight: 850;
            line-height: 1.02;
            text-transform: none;
        }

        .command-title {
            margin: 14px 0 8px;
            color: rgba(255, 255, 255, 0.88);
            font-size: 24px;
            line-height: 1.18;
        }

        .command-text {
            max-width: 740px;
            color: rgba(255, 255, 255, 0.76);
            font-size: 17px;
            line-height: 1.45;
        }

        .must-do {
            display: grid;
            gap: 7px;
            margin-top: 18px;
            max-width: 820px;
            border-radius: 7px;
            padding: 16px;
            background: #f8f2e5;
            color: var(--negro);
            border: 1px solid #d8c89d;
        }

        .must-do span {
            color: #6f521d;
            font-size: 12px;
            font-weight: 850;
            text-transform: uppercase;
        }

        .must-do strong {
            font-size: 22px;
            line-height: 1.22;
        }

        .command-side {
            display: grid;
            gap: 12px;
        }

        .status-tower {
            display: grid;
            gap: 14px;
            align-content: center;
            min-height: 210px;
            border-radius: 7px;
            padding: 18px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.15);
        }

        .status-tower span,
        .side-number span {
            color: rgba(255, 255, 255, 0.72);
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
        }

        .status-tower strong {
            display: block;
            color: white;
            font-size: 36px;
            line-height: 1.02;
            text-transform: none;
        }

        .status-tower small,
        .side-number small {
            color: rgba(255, 255, 255, 0.72);
            font-weight: 800;
            line-height: 1.35;
        }

        .status-light-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .status-dot {
            width: 24px;
            height: 24px;
            border-radius: 999px;
            background: var(--verde);
            box-shadow: none;
        }

        .status-tower.alta .status-dot {
            background: var(--amarillo);
            box-shadow: none;
        }

        .status-tower.saturado .status-dot {
            background: var(--rojo);
            box-shadow: none;
        }

        .side-number-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }

        .side-number {
            border-radius: 7px;
            padding: 14px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.12);
        }

        .side-number strong {
            display: block;
            margin-top: 7px;
            color: white;
            font-size: 28px;
            line-height: 1;
        }

        .vital-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }

        .vital-card,
        .intel-card,
        .operator-action {
            position: relative;
            overflow: hidden;
            border: 1px solid var(--linea);
            border-radius: 7px;
            background: #fffefa;
            padding: 18px;
            box-shadow: none;
        }

        .vital-card {
            min-height: 140px;
        }

        .vital-card::before,
        .intel-card::before {
            content: "";
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 5px;
            background: var(--azul);
        }

        .vital-card.money::before {
            background: var(--verde);
        }

        .vital-card.ticket::before {
            background: var(--azul);
        }

        .vital-card.work::before {
            background: var(--amarillo);
        }

        .vital-card span,
        .intel-card span,
        .operator-action span {
            display: block;
            color: var(--gris);
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
        }

        .vital-card strong {
            display: block;
            margin-top: 12px;
            font-size: 32px;
            line-height: 1;
        }

        .vital-card small,
        .intel-card small,
        .operator-action small {
            display: block;
            margin-top: 10px;
            color: var(--gris);
            font-weight: 700;
            line-height: 1.35;
        }

        .intel-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
        }

        .intel-card {
            min-height: 176px;
        }

        .intel-card.winner::before {
            background: var(--verde);
        }

        .intel-card.slow::before {
            background: var(--rojo);
        }

        .intel-card.chance::before {
            background: var(--azul);
        }

        .intel-card strong {
            display: block;
            margin-top: 12px;
            font-size: 24px;
            line-height: 1.12;
        }

        .intel-card em {
            display: inline-flex;
            width: fit-content;
            margin-top: 14px;
            border-radius: 6px;
            padding: 7px 10px;
            background: white;
            border: 1px solid var(--linea);
            color: var(--negro);
            font-style: normal;
            font-size: 12px;
            font-weight: 800;
        }

        .ops-grid {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 360px;
            gap: 18px;
            align-items: start;
        }

        .operator-actions {
            display: grid;
            gap: 12px;
            margin: 0;
            padding: 0;
            list-style: none;
        }

        .operator-action {
            display: grid;
            gap: 8px;
            border-left: 5px solid var(--dorado);
        }

        .operator-action.alta {
            border-left-color: var(--rojo);
            background: #f5eeee;
        }

        .operator-action.media {
            border-left-color: var(--amarillo);
            background: #fffaf0;
        }

        .operator-action.oportunidad {
            border-left-color: var(--azul);
            background: #f4f4f2;
        }

        .operator-action.normal {
            border-left-color: var(--verde);
            background: #eef3ef;
        }

        .operator-action strong {
            font-size: 23px;
            line-height: 1.12;
            text-transform: none;
        }

        .operator-action p {
            margin: 0;
            font-weight: 800;
        }

        .decision-list {
            display: grid;
            gap: 10px;
            margin: 0;
            padding: 0;
            list-style: none;
        }

        .decision-list li {
            border: 1px solid var(--linea);
            border-left: 5px solid var(--dorado);
            border-radius: 8px;
            background: #fffdf7;
            padding: 12px;
        }

        .decision-list li.alta {
            border-left-color: var(--rojo);
            background: #f5eeee;
        }

        .decision-list li.media {
            border-left-color: var(--amarillo);
            background: #fffaf0;
        }

        .decision-list li.oportunidad {
            border-left-color: var(--azul);
            background: #f4f4f2;
        }

        .decision-tag {
            display: inline-flex;
            border-radius: 999px;
            padding: 4px 8px;
            background: rgba(255, 255, 255, 0.72);
            color: var(--gris);
            font-size: 11px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .two-column {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 330px;
            gap: 18px;
            align-items: start;
        }

        .inventory-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }

        .recipe-list {
            margin: 0;
            padding-left: 18px;
            color: var(--gris);
            font-weight: 700;
        }

        .login-shell {
            min-height: calc(100vh - 80px);
            display: grid;
            place-items: center;
            padding: 24px 0;
        }

        .login-card {
            width: min(430px, 100%);
            padding: 24px;
        }

        .login-logo {
            width: 118px;
            height: 118px;
            margin-bottom: 18px;
            border-radius: 8px;
            overflow: hidden;
            background: var(--negro);
            border: 1px solid #242424;
        }

        .login-logo img {
            width: 100%;
            height: 100%;
            object-fit: contain;
        }

        .access-list {
            display: grid;
            gap: 6px;
            margin-top: 14px;
            color: var(--gris);
            font-size: 13px;
            font-weight: 700;
        }

        .ticket-wrap {
            display: grid;
            justify-content: center;
            gap: 14px;
        }

        .ticket {
            width: min(390px, 100%);
            padding: 20px;
            color: #111;
        }

        .ticket-logo {
            width: 92px;
            height: 92px;
            margin: 0 auto 10px;
            border-radius: 8px;
            overflow: hidden;
            background: #000;
        }

        .ticket-logo img {
            width: 100%;
            height: 100%;
            object-fit: contain;
        }

        .ticket h1 {
            text-align: center;
            font-size: 22px;
        }

        .ticket-meta,
        .ticket-lines {
            margin: 14px 0;
            padding: 14px 0;
            border-top: 1px dashed #bbb;
            border-bottom: 1px dashed #bbb;
        }

        .ticket-row {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            padding: 5px 0;
        }

        .ticket-total {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            font-size: 20px;
            font-weight: 900;
        }

        .kitchen-page {
            background: #f7fbff;
        }

        .kitchen-page .order-card {
            box-shadow: none;
        }

        @media (max-width: 980px) {
            .metrics,
            .workspace,
            .two-column,
            .owner-command,
            .control-hero,
            .console-hero,
            .console-metrics,
            .console-products,
            .console-bottom,
            .command-board,
            .vital-grid,
            .intel-grid,
            .ops-grid,
            .command-grid,
            .product-focus-grid,
            .operation-grid,
            .production-overview,
            .status-grid,
            .business-cards {
                grid-template-columns: 1fr;
            }

            .sticky-panel {
                position: static;
            }

            .order-foot {
                grid-template-columns: 1fr;
            }

            .pay-form {
                justify-content: flex-start;
            }
        }

        @media (max-width: 720px) {
            .topbar-inner,
            .page-head,
            .order-head {
                align-items: stretch;
                flex-direction: column;
            }

            .brand {
                min-width: 0;
            }

            .nav {
                justify-content: flex-start;
            }

            .products li {
                grid-template-columns: 1fr;
            }

            .line-actions {
                justify-content: flex-start;
            }

            .inventory-grid {
                grid-template-columns: 1fr;
            }

            .option-grid,
            .work-meta {
                grid-template-columns: 1fr;
            }

            .stage-row {
                grid-template-columns: 1fr;
            }

            .console-command {
                font-size: 40px;
            }

            .console-hero h2 {
                font-size: 24px;
            }

            .main-order {
                font-size: 42px;
            }

            .command-title {
                font-size: 24px;
            }

            .status-tower strong {
                font-size: 40px;
            }
        }

        @media print {
            .topbar,
            .screen-actions,
            .flash-list {
                display: none !important;
            }

            body {
                background: white;
            }

            .page {
                padding: 0;
            }

            .ticket {
                width: 80mm;
                border: 0;
                box-shadow: none;
            }
        }
    </style>
</head>
<body class="{{ 'kitchen-page' if vista == 'cocina' else '' }}">
    <header class="topbar">
        <div class="topbar-inner">
            <div class="brand">
                <div class="brand-logo">
                    <img src="{{ url_for('static', filename='black-roll-logo.svg') }}" alt="Black Roll Sushi">
                </div>
                <div>
                    <div>Black Roll Sushi</div>
                    <small>Sistema interno{% if rol %} - {{ rol }}{% endif %}</small>
                </div>
            </div>

            {% if usuario %}
                <nav class="nav" aria-label="Navegacion principal">
                    {% for item in nav_items %}
                        <a class="{{ 'active' if vista == item.vista else '' }}" href="{{ item.url }}">{{ item.label }}</a>
                    {% endfor %}
                    <form action="{{ url_for('logout') }}" method="post">
                        <button type="submit">Salir</button>
                    </form>
                </nav>
            {% endif %}
        </div>
    </header>

    <main class="page">
        {% with mensajes = get_flashed_messages(with_categories=true) %}
            {% if mensajes %}
                <div class="flash-list">
                    {% for categoria, mensaje in mensajes %}
                        <div class="flash {{ categoria }}">{{ mensaje }}</div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}

        {{ contenido|safe }}
    </main>

    <script>
        let audioContext;

        function playFeedback(error = false) {
            try {
                audioContext = audioContext || new (window.AudioContext || window.webkitAudioContext)();
                const osc = audioContext.createOscillator();
                const gain = audioContext.createGain();
                osc.type = "sine";
                osc.frequency.value = error ? 180 : 740;
                gain.gain.setValueAtTime(0.001, audioContext.currentTime);
                gain.gain.exponentialRampToValueAtTime(error ? 0.08 : 0.045, audioContext.currentTime + 0.01);
                gain.gain.exponentialRampToValueAtTime(0.001, audioContext.currentTime + 0.12);
                osc.connect(gain);
                gain.connect(audioContext.destination);
                osc.start();
                osc.stop(audioContext.currentTime + 0.13);
            } catch (error) {
                return;
            }
        }

        function showToast(message, category = "success") {
            if (!message) {
                return;
            }
            let toast = document.getElementById("ajax-toast");
            if (!toast) {
                toast = document.createElement("div");
                toast.id = "ajax-toast";
                toast.className = "ajax-toast";
                document.body.appendChild(toast);
            }
            toast.textContent = message;
            toast.className = "ajax-toast " + category;
            window.requestAnimationFrame(() => toast.classList.add("show"));
            clearTimeout(toast.hideTimer);
            toast.hideTimer = setTimeout(() => toast.classList.remove("show"), 1700);
        }

        function applyCajaFragments(data) {
            if (!data || !data.fragments) {
                return;
            }
            const targets = {
                metrics: document.getElementById("metrics-panel"),
                active_order: document.getElementById("active-order-panel"),
                order_select: document.getElementById("pedido_id"),
                orders: document.getElementById("orders-panel"),
            };

            Object.entries(targets).forEach(([key, element]) => {
                if (element && data.fragments[key] !== undefined) {
                    if (key !== "order_select" || element.tagName === "SELECT") {
                        element.innerHTML = data.fragments[key];
                    }
                }
            });

            const pedidoSelect = document.getElementById("pedido_id");
            if (pedidoSelect) {
                pedidoSelect.value = data.pedido_activo_id ? String(data.pedido_activo_id) : "";
            }
        }

        async function sendAjaxForm(form, submitter) {
            const body = new FormData(form);
            if (submitter && submitter.name && !body.has(submitter.name)) {
                body.append(submitter.name, submitter.value);
            }
            submitter?.classList.add("busy");

            try {
                const response = await fetch(form.action, {
                    method: form.method || "POST",
                    body,
                    headers: {
                        "X-Requested-With": "fetch",
                        "Accept": "application/json",
                    },
                });

                if (!response.headers.get("content-type")?.includes("application/json")) {
                    window.location.href = response.url;
                    return;
                }

                const data = await response.json();
                applyCajaFragments(data);
                showToast(data.message, data.category || (data.ok ? "success" : "error"));
                playFeedback(!data.ok);
            } catch (error) {
                showToast("No se pudo actualizar la caja.", "error");
                playFeedback(true);
            } finally {
                submitter?.classList.remove("busy");
            }
        }

        async function activateOrder(url) {
            try {
                const response = await fetch(url, {
                    headers: {
                        "X-Requested-With": "fetch",
                        "Accept": "application/json",
                    },
                });
                const data = await response.json();
                applyCajaFragments(data);
                showToast("Pedido activo seleccionado.", "success");
                playFeedback(false);
            } catch (error) {
                window.location.href = url;
            }
        }

        document.addEventListener("submit", (event) => {
            const form = event.target.closest("form[data-ajax='true']");
            if (!form) {
                return;
            }
            event.preventDefault();
            sendAjaxForm(form, event.submitter);
        });

        document.addEventListener("click", (event) => {
            const card = event.target.closest(".clickable-order");
            if (!card || event.target.closest("a, button, form, input, select, textarea")) {
                return;
            }
            event.preventDefault();
            activateOrder(card.dataset.activeUrl);
        });

        document.addEventListener("click", (event) => {
            const link = event.target.closest("a.button.same[href*='pedido_id=']");
            if (!link) {
                return;
            }
            event.preventDefault();
            activateOrder(link.href);
        });
    </script>
</body>
</html>
"""


HTML_LOGIN = """
<section class="login-shell">
    <div class="login-card">
        <div class="login-logo">
            <img src="{{ url_for('static', filename='black-roll-logo.svg') }}" alt="Black Roll Sushi">
        </div>

        <h1>Black Roll Sushi</h1>
        <p class="muted">Acceso por rol para caja, cocina y administracion.</p>

        <form method="post" class="field-grid">
            <div>
                <label for="usuario_input">Usuario</label>
                <input id="usuario_input" type="text" name="usuario" autocomplete="username" required>
            </div>

            <div>
                <label for="password_input">Contrasena</label>
                <input id="password_input" type="password" name="password" autocomplete="current-password" required>
            </div>

            <button class="button primary" type="submit">Entrar</button>
        </form>

        {% if mostrar_credenciales_demo %}
            <div class="access-list">
                <span>caja / caja123</span>
                <span>cocina / cocina123</span>
                <span>empanizado / empanizado123</span>
                <span>decoracion / decoracion123</span>
                <span>admin / admin123</span>
            </div>
        {% endif %}
    </div>
</section>
"""


HTML_CAJA_METRICS_INNER = """
<div class="metric">
    <span>Ingresos hoy</span>
    <strong>${{ total_ingresos }}</strong>
</div>
<div class="metric">
    <span>Vendido hoy</span>
    <strong>${{ total_ventas }}</strong>
</div>
<div class="metric">
    <span>En armado</span>
    <strong>{{ conteo.armado + conteo.pendiente }}</strong>
</div>
<div class="metric">
    <span>Empanizado</span>
    <strong>{{ conteo.empanizado }}</strong>
</div>
<div class="metric">
    <span>Decoracion</span>
    <strong>{{ conteo.decoracion }}</strong>
</div>
"""


HTML_PEDIDO_SELECT_OPTIONS = """
<option value="" {{ 'selected' if not pedido_activo_id else '' }}>Crear pedido nuevo</option>
{% for pedido in pedidos %}
    <option value="{{ pedido.id }}" {{ 'selected' if pedido.id == pedido_activo_id else '' }}>
        Agregar a #{{ pedido.id }} - {{ pedido.cliente }}{% if pedido.telefono %} - {{ pedido.telefono }}{% endif %} - ${{ pedido.total }}
    </option>
{% endfor %}
"""


HTML_PEDIDO_ACTIVO_INNER = """
{% if pedido_activo %}
    <div class="active-strip">
        <span>Pedido activo: #{{ pedido_activo.id }} - {{ pedido_activo.cliente }}</span>
        <small class="muted">
            {% if pedido_activo.telefono %}Tel: {{ pedido_activo.telefono }} - {% endif %}
            {{ pedido_activo.total_items }} productos - {{ pedido_activo.edad_texto }} abierto
        </small>
        <a class="button compact ghost" href="{{ url_for('index', nuevo=1) }}">Nuevo pedido</a>
    </div>
{% else %}
    <div class="active-strip">
        <span>Pedido nuevo</span>
        <small class="muted">Escribe cliente y toca un producto para iniciar. Telefono opcional.</small>
    </div>
{% endif %}
"""


HTML_PEDIDOS_ABIERTOS_INNER = """
<h2>Pedidos abiertos</h2>

{% if pedidos %}
    <div class="orders">
        {% for pedido in pedidos %}
            <article
                class="order-card clickable-order {{ pedido.estado }} {{ 'activo' if pedido.id == pedido_activo_id else '' }}"
                data-active-url="{{ url_for('index', pedido_id=pedido.id) }}"
            >
                <div class="order-head">
                    <div>
                        <h3 class="order-title">#{{ pedido.id }} - {{ pedido.cliente }}</h3>
                        <p class="muted">
                            {{ pedido.folio }} - {{ pedido.fecha }} - {{ pedido.edad_texto }}
                            {% if pedido.telefono %}- Tel: {{ pedido.telefono }}{% endif %}
                        </p>
                    </div>

                    <div class="actions">
                        <span class="badge {{ pedido.estado }}">{{ pedido.estado }}</span>
                        <a class="button compact same" href="{{ url_for('index', pedido_id=pedido.id) }}">Activar</a>
                    </div>
                </div>

                {% if pedido.productos %}
                    <ul class="products">
                        {% for prod in pedido.productos %}
                            <li>
                                <div class="line-main">
                                    <strong>{{ prod.producto }} x{{ prod.cantidad }}</strong>
                                    <span>${{ prod.precio }} c/u</span>
                                </div>

                                <strong>${{ prod.precio * prod.cantidad }}</strong>

                                <div class="line-actions">
                                    {% if prod.etapa == "armado_pendiente" %}
                                        <form action="{{ url_for('sumar_producto', pedido_id=pedido.id, linea_id=prod.id) }}" method="post" data-ajax="true">
                                            <button class="button compact same" type="submit">+1 igual</button>
                                        </form>
                                        <form action="{{ url_for('restar_producto', pedido_id=pedido.id, linea_id=prod.id) }}" method="post" data-ajax="true">
                                            <button class="qty-button" type="submit" title="Restar">-</button>
                                        </form>
                                    {% endif %}
                                    <form action="{{ url_for('eliminar_producto', pedido_id=pedido.id, linea_id=prod.id) }}" method="post" data-ajax="true">
                                        <button class="button compact ghost" type="submit">Quitar</button>
                                    </form>
                                    <a class="button compact" href="{{ url_for('editar_producto', linea_id=prod.id) }}">Editar</a>
                                </div>

                                <div class="line-details">
                                    <span class="stage-chip {{ prod.etapa }}">{{ etapa_nombre(prod.etapa) }}</span>
                                    {% if prod.preparacion != "natural" %}
                                        <span class="detail-chip">{{ prod.preparacion }}</span>
                                    {% endif %}
                                    {% if prod.por_dentro %}
                                        <span>Por dentro: {{ prod.por_dentro }}</span>
                                    {% endif %}
                                    {% if prod.quitar %}
                                        <span>Quitar: {{ prod.quitar }}</span>
                                    {% endif %}
                                    {% if prod.terminado %}
                                        <span>Terminado: {{ prod.terminado }}</span>
                                    {% endif %}
                                    {% if prod.extras %}
                                        <span>Extras: {{ prod.extras }}</span>
                                    {% endif %}
                                    {% if prod.notas %}
                                        <span>Notas: {{ prod.notas }}</span>
                                    {% endif %}
                                </div>
                            </li>
                        {% endfor %}
                    </ul>
                {% else %}
                    <div class="empty">Este pedido no tiene productos.</div>
                {% endif %}

                <div class="order-foot">
                    <div class="order-total">Total: ${{ pedido.total }}</div>

                    <div class="actions">
                        {% if pedido.estado == "listo" %}
                            <form class="pay-form" action="{{ url_for('cobrar', pedido_id=pedido.id) }}" method="post">
                                <select name="metodo_pago" aria-label="Metodo de pago">
                                    {% for metodo in metodos_pago %}
                                        <option value="{{ metodo.id }}">{{ metodo.nombre }}</option>
                                    {% endfor %}
                                </select>
                                <button class="button danger" type="submit">Cobrar</button>
                            </form>
                        {% else %}
                            <span class="muted">Pendiente de {{ pedido.estado }}.</span>
                        {% endif %}

                        <form action="{{ url_for('cancelar_pedido', pedido_id=pedido.id) }}" method="post">
                            <button class="button ghost" type="submit" onclick="return confirm('Cancelar este pedido?')">Cancelar</button>
                        </form>
                    </div>
                </div>
            </article>
        {% endfor %}
    </div>
{% else %}
    <div class="empty">No hay pedidos abiertos.</div>
{% endif %}

<div class="panel" style="margin-top: 18px;">
    <h2>Corte de hoy</h2>
    <p class="muted">{{ fecha_hoy }}</p>

    <div class="metrics" style="grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 0;">
        {% for metodo in metodos_pago %}
            <div class="metric">
                <span>{{ metodo.nombre }}</span>
                <strong>${{ totales_metodo.get(metodo.id, 0) }}</strong>
            </div>
        {% endfor %}
    </div>
</div>
"""


HTML_CAJA = """
<section class="page-head">
    <div>
        <h1>Caja</h1>
        <p class="muted">Pedidos activos, cobro y corte del dia.</p>
    </div>
</section>

<section id="metrics-panel" class="metrics">
    <div class="metric">
        <span>Ingresos hoy</span>
        <strong>${{ total_ingresos }}</strong>
    </div>
    <div class="metric">
        <span>Pedidos activos</span>
        <strong>{{ pedidos|length }}</strong>
    </div>
    <div class="metric">
        <span>En produccion</span>
        <strong>{{ conteo.armado + conteo.pendiente + conteo.empanizado + conteo.decoracion }}</strong>
    </div>
    <div class="metric">
        <span>Listos</span>
        <strong>{{ conteo.listo }}</strong>
    </div>
</section>

<section class="workspace">
    <div class="panel sticky-panel">
        <h2>Agregar productos</h2>

        <form id="add-product-form" action="{{ url_for('agregar_producto') }}" method="post" data-ajax="true">
            <div class="field-grid">
                <div>
                    <label for="cliente">Cliente</label>
                    <input id="cliente" type="text" name="cliente" placeholder="Ej. Juan Perez">
                </div>

                <div>
                    <label for="telefono">Telefono <span class="muted">(opcional)</span></label>
                    <input id="telefono" type="tel" inputmode="tel" name="telefono" placeholder="Opcional">
                </div>

                <input id="pedido_id" type="hidden" name="pedido_id" value="{{ pedido_activo_id or '' }}">

                <div id="active-order-panel">
                    {% if pedido_activo %}
                        <div class="active-strip">
                            <span>Pedido activo: #{{ pedido_activo.id }} - {{ pedido_activo.cliente }}</span>
                            <small class="muted">
                                {% if pedido_activo.telefono %}Tel: {{ pedido_activo.telefono }} - {% endif %}
                                {{ pedido_activo.total_items }} productos - {{ pedido_activo.edad_texto }} abierto
                            </small>
                            <a class="button compact ghost" href="{{ url_for('index', nuevo=1) }}">Nuevo pedido</a>
                        </div>
                    {% else %}
                        <div class="active-strip">
                            <span>Pedido nuevo</span>
                            <small class="muted">Escribe cliente y toca un producto para iniciar. Telefono opcional.</small>
                        </div>
                    {% endif %}
                </div>

                <p class="muted" style="margin: 0;">
                    Agrega productos al pedido activo. Edita solo cuando haya cambios.
                </p>
            </div>

            {% for categoria, items in menu_categorias.items() %}
                <div class="category">
                    <div class="category-title">
                        <span>{{ categoria }}</span>
                        <small class="muted">{{ items|length }} productos</small>
                    </div>

                    <div class="menu-grid">
                        {% for item in items %}
                            <button class="menu-item" name="producto_id" value="{{ item.id }}" type="submit">
                                <span>
                                    <strong>{{ item.nombre }}</strong>
                                    <small>{{ item.categoria }}</small>
                                </span>
                                <span class="price">${{ item.precio }}</span>
                            </button>
                        {% endfor %}
                    </div>
                </div>
            {% endfor %}
        </form>
    </div>

    <div id="orders-panel">
        <h2>Pedidos abiertos</h2>

        {% if pedidos %}
            <div class="orders">
                {% for pedido in pedidos %}
                    <article
                        class="order-card clickable-order {{ pedido.estado }} {{ 'activo' if pedido.id == pedido_activo_id else '' }}"
                        data-active-url="{{ url_for('index', pedido_id=pedido.id) }}"
                    >
                        <div class="order-head">
                            <div>
                                <h3 class="order-title">#{{ pedido.id }} - {{ pedido.cliente }}</h3>
                                <p class="muted">
                                    {{ pedido.folio }} - {{ pedido.fecha }} - {{ pedido.edad_texto }}
                                    {% if pedido.telefono %}- Tel: {{ pedido.telefono }}{% endif %}
                                </p>
                            </div>

                            <div class="actions">
                                <span class="badge {{ pedido.estado }}">{{ pedido.estado }}</span>
                                <a class="button compact same" href="{{ url_for('index', pedido_id=pedido.id) }}">Activar</a>
                            </div>
                        </div>

                        {% if pedido.productos %}
                            <ul class="products">
                                {% for prod in pedido.productos %}
                                    <li>
                                        <div class="line-main">
                                            <strong>{{ prod.producto }} x{{ prod.cantidad }}</strong>
                                            <span>${{ prod.precio }} c/u</span>
                                        </div>

                                        <strong>${{ prod.precio * prod.cantidad }}</strong>

                                        <div class="line-actions">
                                            {% if prod.etapa == "armado_pendiente" %}
                                                <form action="{{ url_for('sumar_producto', pedido_id=pedido.id, linea_id=prod.id) }}" method="post" data-ajax="true">
                                                    <button class="button compact same" type="submit">+1 igual</button>
                                                </form>
                                                <form action="{{ url_for('restar_producto', pedido_id=pedido.id, linea_id=prod.id) }}" method="post" data-ajax="true">
                                                    <button class="qty-button" type="submit" title="Restar">-</button>
                                                </form>
                                            {% endif %}
                                            <form action="{{ url_for('eliminar_producto', pedido_id=pedido.id, linea_id=prod.id) }}" method="post" data-ajax="true">
                                                <button class="button compact ghost" type="submit">Quitar</button>
                                            </form>
                                            <a class="button compact" href="{{ url_for('editar_producto', linea_id=prod.id) }}">Editar</a>
                                        </div>

                                        <div class="line-details">
                                            <span class="stage-chip {{ prod.etapa }}">{{ etapa_nombre(prod.etapa) }}</span>
                                            {% if prod.preparacion != "natural" %}
                                                <span class="detail-chip">{{ prod.preparacion }}</span>
                                            {% endif %}
                                            {% if prod.por_dentro %}
                                                <span>Por dentro: {{ prod.por_dentro }}</span>
                                            {% endif %}
                                            {% if prod.quitar %}
                                                <span>Quitar: {{ prod.quitar }}</span>
                                            {% endif %}
                                            {% if prod.terminado %}
                                                <span>Terminado: {{ prod.terminado }}</span>
                                            {% endif %}
                                            {% if prod.extras %}
                                                <span>Extras: {{ prod.extras }}</span>
                                            {% endif %}
                                            {% if prod.notas %}
                                                <span>Notas: {{ prod.notas }}</span>
                                            {% endif %}
                                        </div>
                                    </li>
                                {% endfor %}
                            </ul>
                        {% else %}
                            <div class="empty">Este pedido no tiene productos.</div>
                        {% endif %}

                        <div class="order-foot">
                            <div class="order-total">Total: ${{ pedido.total }}</div>

                            <div class="actions">
                                {% if pedido.estado == "listo" %}
                                    <form class="pay-form" action="{{ url_for('cobrar', pedido_id=pedido.id) }}" method="post">
                                        <select name="metodo_pago" aria-label="Metodo de pago">
                                            {% for metodo in metodos_pago %}
                                                <option value="{{ metodo.id }}">{{ metodo.nombre }}</option>
                                            {% endfor %}
                                        </select>
                                        <button class="button danger" type="submit">Cobrar</button>
                                    </form>
                                {% else %}
                                    <span class="muted">Pendiente de {{ pedido.estado }}.</span>
                                {% endif %}

                                <form action="{{ url_for('cancelar_pedido', pedido_id=pedido.id) }}" method="post">
                                    <button class="button ghost" type="submit" onclick="return confirm('Cancelar este pedido?')">Cancelar</button>
                                </form>
                            </div>
                        </div>
                    </article>
                {% endfor %}
            </div>
        {% else %}
            <div class="empty">No hay pedidos abiertos.</div>
        {% endif %}

        <div class="panel" style="margin-top: 18px;">
            <h2>Corte de hoy</h2>
            <p class="muted">{{ fecha_hoy }}</p>

            <div class="metrics" style="grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 0;">
                {% for metodo in metodos_pago %}
                    <div class="metric">
                        <span>{{ metodo.nombre }}</span>
                        <strong>${{ totales_metodo.get(metodo.id, 0) }}</strong>
                    </div>
                {% endfor %}
            </div>
        </div>
    </div>
</section>
"""


HTML_COCINA = """
<section class="page-head">
    <div>
        <h1>Cocina</h1>
        <p class="muted">Prioridad para pedidos pendientes y vista clara de productos.</p>
    </div>
</section>

<section class="metrics">
    <div class="metric">
        <span>Pendientes</span>
        <strong>{{ conteo.pendiente }}</strong>
    </div>
    <div class="metric">
        <span>Listos</span>
        <strong>{{ conteo.listo }}</strong>
    </div>
    <div class="metric">
        <span>Pedidos abiertos</span>
        <strong>{{ pedidos|length }}</strong>
    </div>
    <div class="metric">
        <span>Hora</span>
        <strong>{{ hora }}</strong>
    </div>
</section>

{% if pedidos %}
    <div class="orders">
        {% for pedido in pedidos %}
            <article class="order-card {{ pedido.estado }}">
                <div class="order-head">
                    <div>
                        <h2 class="order-title">#{{ pedido.id }} - {{ pedido.cliente }}</h2>
                        <p class="muted">{{ pedido.folio }} - {{ pedido.fecha }}</p>
                    </div>

                    <span class="badge {{ pedido.estado }}">{{ pedido.estado }}</span>
                </div>

                <ul class="products">
                    {% for prod in pedido.productos %}
                        <li>
                            <div class="line-main">
                                <strong>{{ prod.producto }}</strong>
                                <span>${{ prod.precio }} c/u</span>
                            </div>
                            <strong>x{{ prod.cantidad }}</strong>
                            <strong>${{ prod.precio * prod.cantidad }}</strong>
                        </li>
                    {% endfor %}
                </ul>

                <div class="order-foot">
                    <div class="order-total">Total: ${{ pedido.total }}</div>

                    {% if pedido.estado == "pendiente" %}
                        <form action="{{ url_for('marcar_listo', pedido_id=pedido.id) }}" method="post">
                            <button class="button ready" type="submit">Marcar listo</button>
                        </form>
                    {% else %}
                        <strong style="color: var(--verde);">Listo para entregar</strong>
                    {% endif %}
                </div>
            </article>
        {% endfor %}
    </div>
{% else %}
    <div class="empty">No hay pedidos para cocina.</div>
{% endif %}
"""


HTML_VENTAS = """
<section class="page-head">
    <div>
        <h1>Historial de ventas</h1>
        <p class="muted">Consulta por fecha, metodo de pago y ticket.</p>
    </div>

    <form class="filters" method="get">
        <input type="date" name="fecha" value="{{ fecha }}">
        <button class="button primary" type="submit">Buscar</button>
        <a class="button ghost" href="{{ url_for('ventas_historial') }}">Hoy</a>
        <a class="button" href="{{ url_for('exportar_ventas', fecha=fecha) }}">Exportar CSV</a>
    </form>
</section>

<section class="metrics">
    <div class="metric">
        <span>Ingresos</span>
        <strong>${{ total_ingresos }}</strong>
    </div>
    <div class="metric">
        <span>Vendido</span>
        <strong>${{ total_ventas }}</strong>
    </div>
    <div class="metric">
        <span>Tickets</span>
        <strong>{{ ventas|length }}</strong>
    </div>
    <div class="metric">
        <span>Fecha</span>
        <strong>{{ fecha }}</strong>
    </div>
</section>

<section class="two-column">
    <div class="panel">
        <h2>Ventas</h2>

        {% if ventas %}
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Folio</th>
                        <th>Hora</th>
                        <th>Cliente</th>
                        <th>Telefono</th>
                        <th>Pago</th>
                        <th>Total</th>
                        <th>Ticket</th>
                    </tr>
                </thead>
                <tbody>
                    {% for venta in ventas %}
                        <tr>
                            <td>{{ venta.folio or ("BR-" ~ "%04d"|format(venta.id)) }}</td>
                            <td>{{ venta.fecha[11:16] }}</td>
                            <td>{{ venta.cliente }}</td>
                            <td>{{ venta.telefono or "-" }}</td>
                            <td>{{ metodo_nombre(venta.metodo_pago) }}</td>
                            <td><strong>${{ venta.total }}</strong></td>
                            <td><a class="button compact" href="{{ url_for('ticket', venta_id=venta.id) }}">Ver</a></td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <div class="empty">No hay ventas en esta fecha.</div>
        {% endif %}
    </div>

    <aside class="panel">
        <h2>Por metodo</h2>

        <table class="data-table">
            <tbody>
                {% for metodo in metodos_pago %}
                    <tr>
                        <td>{{ metodo.nombre }}</td>
                        <td><strong>${{ totales_metodo.get(metodo.id, 0) }}</strong></td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    </aside>
</section>
"""


HTML_PRODUCCION = """
<section class="page-head">
    <div>
        <h1>Produccion</h1>
        <p class="muted">Pedidos en curso, carga por estacion y tiempos del dia.</p>
    </div>

    <form class="filters" method="get">
        <input type="date" name="fecha" value="{{ fecha }}">
        <button class="button primary" type="submit">Buscar</button>
        <a class="button ghost" href="{{ url_for('produccion') }}">Hoy</a>
    </form>
</section>

<section class="metrics">
    <div class="metric">
        <span>Estado del dia</span>
        <strong>{{ resumen.estado_carga }}</strong>
    </div>
    <div class="metric">
        <span>Piezas activas</span>
        <strong>{{ resumen.piezas_activas }}</strong>
    </div>
    <div class="metric">
        <span>Entraron 10 min</span>
        <strong>{{ resumen.nuevos_10_min }}</strong>
    </div>
    <div class="metric">
        <span>Pedidos pendientes</span>
        <strong>{{ resumen.pedidos_pendientes }}</strong>
    </div>
    <div class="metric">
        <span>Promedio</span>
        <strong>{{ resumen.promedio_total }} min</strong>
    </div>
</section>

<section class="production-overview">
    <div class="panel">
        <h2>Por estacion</h2>

        <div class="stage-list">
            {% for estacion in carga_estaciones %}
                <div class="stage-row {{ estacion.estado_id }}">
                    <strong>{{ estacion.nombre }}</strong>
                    <div class="stage-bar" title="{{ estacion.piezas_activas }} sushis activos">
                        <div class="stage-fill" style="--value: {{ estacion.piezas_activas }};"></div>
                    </div>
                    <span class="load-chip {{ estacion.estado_id }}">{{ estacion.estado }}</span>
                    <small class="muted">{{ estacion.piezas_activas }} activos - {{ estacion.piezas_nuevas_10 }} nuevos - {{ estacion.promedio }} min prom.</small>
                </div>
            {% endfor %}
        </div>

        <div class="status-grid">
            <div class="status-box">
                <span>Etapas cerradas</span>
                <strong>{{ total_cerrados }}</strong>
            </div>
            <div class="status-box">
                <span>Piezas activas</span>
                <strong>{{ resumen.piezas_activas }}</strong>
            </div>
            <div class="status-box">
                <span>Nuevos ult. 10 min</span>
                <strong>{{ resumen.nuevos_10_min }}</strong>
            </div>
        </div>
    </div>

    <aside class="panel bottleneck {{ resumen.mayor_carga_estado_id }}">
        <span class="muted">Mas carga ahora</span>
        <strong>{{ resumen.mayor_carga }}</strong>
        <p class="muted">{{ resumen.mayor_carga_piezas }} sushis activos - {{ resumen.mayor_carga_nuevos }} nuevos en 10 min</p>

        {% if resumen.mayor_carga_estado_id == "saturado" %}
            <p><strong style="color: var(--rojo);">Saturado: conviene meter apoyo o avisar mas tiempo.</strong></p>
        {% elif resumen.mayor_carga_estado_id == "alta" %}
            <p><strong style="color: var(--amarillo);">Alta demanda: vigilar prioridades y tiempos prometidos.</strong></p>
        {% else %}
            <p><strong style="color: var(--verde);">Flujo estable.</strong></p>
        {% endif %}
    </aside>
</section>

<section class="two-column">
    <div class="panel">
        <h2>Pedidos activos</h2>

        {% if abiertos %}
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Folio</th>
                        <th>Producto</th>
                        <th>Etapa</th>
                        <th>Entrada</th>
                        <th>Tiempo</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in abiertos %}
                        <tr>
                            <td>{{ item.folio }}</td>
                            <td>{{ item.producto }} x{{ item.cantidad }}</td>
                            <td>{{ etapa_nombre(item.etapa) }}</td>
                            <td>{{ item.fecha_entrada[11:16] }}</td>
                            <td><span class="timer">{{ item.tiempo_abierto }}</span></td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <div class="empty">No hay productos abiertos en produccion.</div>
        {% endif %}
    </div>

    <aside class="panel">
        <h2>Carga alta</h2>

        {% if demanda_estaciones %}
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Estacion</th>
                        <th>Activos</th>
                        <th>Estado</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in demanda_estaciones %}
                        <tr>
                            <td>{{ item.nombre }}</td>
                            <td>{{ item.piezas_activas }} · {{ item.piezas_nuevas_10 }} nuevos</td>
                            <td><span class="load-chip {{ item.estado_id }}">{{ item.estado }}</span></td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <div class="empty">Carga normal en todas las estaciones.</div>
        {% endif %}
    </aside>
</section>

<section class="two-column" style="margin-top: 18px;">
    <div class="panel">
        <h2>Completados del dia</h2>

        {% if completados %}
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Folio</th>
                        <th>Producto</th>
                        <th>Etapas</th>
                        <th>Total</th>
                        <th>Fin</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in completados %}
                        <tr>
                            <td>{{ item.folio }}</td>
                            <td>{{ item.producto }} x{{ item.cantidad }}</td>
                            <td>{{ item.etapas }}</td>
                            <td><strong>{{ item.tiempo_total }} min</strong></td>
                            <td>{{ item.fecha_fin[11:16] }}</td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <div class="empty">Todavia no hay productos completados hoy.</div>
        {% endif %}
    </div>

    <aside class="panel">
        <h2>Cierres por usuario</h2>

        {% if productividad %}
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Usuario</th>
                        <th>Etapa</th>
                        <th>Prom.</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in productividad %}
                        <tr>
                            <td>{{ item.usuario }}</td>
                            <td>{{ etapa_nombre(item.etapa) }} · {{ item.completadas }}</td>
                            <td><strong>{{ item.promedio }} min</strong></td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <div class="empty">Aun no hay cierres registrados hoy.</div>
        {% endif %}
    </aside>
</section>

<section class="two-column" style="margin-top: 18px;">
    <div class="panel">
        <h2>Productos con mayor tiempo promedio</h2>

        {% if productos_lentos %}
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Producto</th>
                        <th>Registros</th>
                        <th>Promedio total</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in productos_lentos %}
                        <tr>
                            <td>{{ item.producto }}</td>
                            <td>{{ item.productos }}</td>
                            <td><strong>{{ item.promedio_total }} min</strong></td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <div class="empty">Todavia no hay datos suficientes por producto.</div>
        {% endif %}
    </div>

    <aside class="panel">
        <h2>Historial reciente</h2>

        {% if historial %}
            <table class="data-table">
                <tbody>
                    {% for item in historial[:10] %}
                        <tr>
                            <td>{{ item.folio }} · {{ etapa_nombre(item.etapa) }}</td>
                            <td>
                                {% if item.duracion_minutos is not none %}
                                    <strong>{{ item.duracion_minutos }} min</strong>
                                {% else %}
                                    <span class="timer">Abierto</span>
                                {% endif %}
                            </td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <div class="empty">Sin movimientos recientes.</div>
        {% endif %}
    </aside>
</section>
"""


HTML_NEGOCIO = """
<section class="page-head">
    <div>
        <h1>Resumen del dia</h1>
        <p class="muted">Ventas, pedidos y decisiones para Black Roll Sushi.</p>
    </div>

    <form class="filters" method="get">
        <input type="date" name="fecha" value="{{ fecha }}">
        <button class="button primary" type="submit">Buscar</button>
        <a class="button ghost" href="{{ url_for('negocio') }}">Hoy</a>
    </form>
</section>

<section class="command-room">
    <section class="panel command-board {{ decision_principal.prioridad }}">
        <div class="command-main">
            <span class="command-eyebrow">Decision del dia</span>
            <strong class="main-order">{{ decision_principal.orden }}</strong>
            <h2 class="command-title">{{ decision_principal.titulo }}</h2>
            <p class="command-text">{{ decision_principal.texto }}</p>

            <div class="must-do">
                <span>Accion</span>
                <strong>{{ decision_principal.accion }}</strong>
            </div>
        </div>

        <aside class="command-side">
            <div class="status-tower {{ resumen.estado_operacion_id }}">
                <div class="status-light-row">
                    <span>Estado</span>
                    <i class="status-dot" aria-hidden="true"></i>
                </div>
                <strong>{{ resumen.estado_operacion }}</strong>
                <small>{{ resumen.mensaje_operacion }}</small>
            </div>

            <div class="side-number-grid">
                <div class="side-number">
                    <span>Pedidos abiertos</span>
                    <strong>{{ resumen.pedidos_abiertos }}</strong>
                    <small>Por cerrar</small>
                </div>

                <div class="side-number">
                    <span>Nuevas 10 min</span>
                    <strong>{{ resumen.piezas_nuevas_10 }}</strong>
                    <small>Demanda reciente</small>
                </div>
            </div>
        </aside>
    </section>

    <section class="panel console-section">
        <div class="section-title-row">
            <div>
                <h2>Resumen principal</h2>
                <p class="muted">Ventas, pedidos y trabajo en curso.</p>
            </div>
        </div>

        <div class="vital-grid">
            <div class="vital-card money">
                <span>Ventas</span>
                <strong>${{ resumen.ventas_dia }}</strong>
                <small>Cobrado hoy sin cortesias</small>
            </div>

            <div class="vital-card ticket">
                <span>Ticket promedio</span>
                <strong>${{ resumen.ticket_promedio }}</strong>
                <small>Subelo con combos y extras</small>
            </div>

            <div class="vital-card work">
                <span>Piezas en curso</span>
                <strong>{{ resumen.piezas_activas }}</strong>
                <small>Sushis vivos en produccion</small>
            </div>

            <div class="vital-card work">
                <span>Pedidos activos</span>
                <strong>{{ resumen.pedidos_abiertos }}</strong>
                <small>Pendientes de terminar o cobrar</small>
            </div>
        </div>
    </section>

    <section class="panel console-section">
        <div class="section-title-row">
            <div>
                <h2>Productos clave</h2>
                <p class="muted">Lo que mas se vende, lo que tarda y lo que conviene mover.</p>
            </div>
        </div>

        <div class="intel-grid">
            <div class="intel-card winner">
                <span>Mas vendido</span>
                <strong>{{ resumen.producto_mas_vendido }}</strong>
                <small>{{ resumen.producto_mas_vendido_cantidad }} piezas vendidas</small>
                <em>Promover y acelerar</em>
            </div>

            <div class="intel-card slow">
                <span>Mas lento</span>
                <strong>{{ resumen.producto_mas_lento }}</strong>
                <small>{{ resumen.producto_mas_lento_tiempo }} min promedio</small>
                <em>Subir precio o limitar en pico</em>
            </div>

            <div class="intel-card chance">
                <span>Oportunidad</span>
                <strong>{{ oportunidad.orden }}</strong>
                <small>{{ oportunidad.texto }}</small>
                <em>{{ oportunidad.accion }}</em>
            </div>
        </div>
    </section>

    <section class="ops-grid">
        <div class="panel console-section">
            <div class="section-title-row">
                <div>
                <h2>Decisiones del dia</h2>
                <p class="muted">Acciones cortas para caja y produccion.</p>
                </div>
            </div>

            <ul class="operator-actions">
                {% for decision in decisiones %}
                    <li class="operator-action {{ decision.prioridad }}">
                        <span>{{ decision.etiqueta }}</span>
                        <strong>{{ decision.orden }}</strong>
                        <p>{{ decision.accion }}</p>
                        <small>{{ decision.texto }}</small>
                    </li>
                {% endfor %}
            </ul>
        </div>

        <aside class="panel console-section">
            <h2>Produccion</h2>

            <div class="operation-state {{ resumen.estado_operacion_id }}" style="margin-bottom: 12px;">
                <span>Estado</span>
                <strong>{{ resumen.estado_operacion }}</strong>
                <small>{{ resumen.mensaje_operacion }}</small>
            </div>

            <div class="operation-card" style="margin-bottom: 12px;">
                <span>Tickets</span>
                <strong>{{ resumen.tickets }}</strong>
                <small>Ventas cerradas hoy.</small>
            </div>

            <h2>Modo red WiFi</h2>
            <div class="active-strip">
                <span>{{ red_local }}</span>
                <small class="muted">Caja, armado, empanizado y decoracion en la misma red.</small>
            </div>

            <form action="{{ url_for('respaldar') }}" method="post" style="margin-top: 14px;">
                <button class="button primary" type="submit">Descargar respaldo</button>
            </form>
        </aside>
    </section>
</section>
"""

HTML_TICKET = """
<section class="ticket-wrap">
    <div class="ticket">
        <div class="ticket-logo">
            <img src="{{ url_for('static', filename='black-roll-logo.svg') }}" alt="Black Roll Sushi">
        </div>

        <h1>Black Roll Sushi</h1>

        <div class="ticket-meta">
            <div class="ticket-row">
                <span>Folio</span>
                <strong>{{ venta.folio or ("BR-" ~ "%04d"|format(venta.id)) }}</strong>
            </div>
            <div class="ticket-row">
                <span>Fecha</span>
                <strong>{{ venta.fecha }}</strong>
            </div>
            <div class="ticket-row">
                <span>Cliente</span>
                <strong>{{ venta.cliente }}</strong>
            </div>
            {% if venta.telefono %}
                <div class="ticket-row">
                    <span>Telefono</span>
                    <strong>{{ venta.telefono }}</strong>
                </div>
            {% endif %}
            <div class="ticket-row">
                <span>Pago</span>
                <strong>{{ metodo_nombre(venta.metodo_pago) }}</strong>
            </div>
        </div>

        <div class="ticket-lines">
            {% for prod in productos %}
                <div class="ticket-row">
                    <span>
                        {{ prod.producto }} x{{ prod.cantidad }}
                        {% if prod.preparacion != "natural" %}<br>{{ prod.preparacion|title }}{% endif %}
                        {% if prod.por_dentro %}<br>Dentro: {{ prod.por_dentro }}{% endif %}
                        {% if prod.quitar %}<br>Quitar: {{ prod.quitar }}{% endif %}
                        {% if prod.terminado %}<br>Terminado: {{ prod.terminado }}{% endif %}
                        {% if prod.extras %}<br>Extras: {{ prod.extras }}{% endif %}
                        {% if prod.notas %}<br>Notas: {{ prod.notas }}{% endif %}
                    </span>
                    <strong>${{ prod.precio * prod.cantidad }}</strong>
                </div>
            {% endfor %}
        </div>

        <div class="ticket-total">
            <span>Total</span>
            <span>${{ venta.total }}</span>
        </div>
    </div>

    <div class="screen-actions">
        <button class="button primary" type="button" onclick="window.print()">Imprimir</button>
        <a class="button" href="{{ url_for('ventas_historial', fecha=venta.fecha[:10]) }}">Ventas</a>
        <a class="button ghost" href="{{ url_for('index') }}">Caja</a>
    </div>
</section>
"""


HTML_EDITAR_PRODUCTO = """
<section class="page-head">
    <div>
        <h1>Editar producto</h1>
        <p class="muted">Pedido #{{ pedido.id }} - {{ pedido.cliente }}{% if pedido.telefono %} - Tel: {{ pedido.telefono }}{% endif %}</p>
    </div>
    <a class="button ghost" href="{{ url_for('index', pedido_id=pedido.id) }}">Volver a caja</a>
</section>

<section class="panel">
    <h2>{{ producto.producto }} x{{ producto.cantidad }}</h2>

    <form method="post" class="field-grid">
        <div>
            <label for="preparacion">Preparacion</label>
            <select id="preparacion" name="preparacion">
                {% for preparacion in preparaciones %}
                    <option value="{{ preparacion.id }}" {{ 'selected' if producto.preparacion == preparacion.id else '' }}>
                        {{ preparacion.nombre }}
                    </option>
                {% endfor %}
            </select>
        </div>

        <div>
            <div class="quick-title">
                <label for="por_dentro">Por dentro</label>
                <small class="muted">Rapido</small>
            </div>
            <div class="option-grid">
                {% for opcion in por_dentro_opciones %}
                    <label class="checkbox-pill">
                        <input type="checkbox" name="por_dentro_opciones" value="{{ opcion }}" {{ 'checked' if opcion in producto.por_dentro else '' }}>
                        <span>{{ opcion }}</span>
                    </label>
                {% endfor %}
            </div>
            <input id="por_dentro" style="margin-top: 8px;" type="text" name="por_dentro" value="" placeholder="Otro ingrediente por dentro">
        </div>

        <div>
            <label>Quitar en armado</label>
            <div class="option-grid">
                {% for opcion in quitar_opciones %}
                    <label class="checkbox-pill">
                        <input type="checkbox" name="quitar" value="{{ opcion }}" {{ 'checked' if opcion in producto.quitar else '' }}>
                        <span>{{ opcion }}</span>
                    </label>
                {% endfor %}
            </div>
            <input style="margin-top: 8px;" type="text" name="quitar_extra" placeholder="Otro ingrediente a quitar">
        </div>

        <div>
            <label>Terminado y toppings</label>
            <div class="option-grid">
                {% for opcion in terminado_opciones %}
                    <label class="checkbox-pill">
                        <input type="checkbox" name="terminado" value="{{ opcion }}" {{ 'checked' if opcion in producto.terminado else '' }}>
                        <span>{{ opcion }}</span>
                    </label>
                {% endfor %}
            </div>
            <input style="margin-top: 8px;" type="text" name="extras" value="{{ producto.extras }}" placeholder="Otros extras o salsas">
        </div>

        <div>
            <label for="notas">Notas especiales</label>
            <textarea id="notas" name="notas">{{ producto.notas }}</textarea>
        </div>

        <div class="actions">
            <button class="button primary" type="submit">Guardar cambios</button>
            <a class="button ghost" href="{{ url_for('index', pedido_id=pedido.id) }}">Cancelar</a>
        </div>
    </form>
</section>
"""


HTML_INVENTARIO = """
<section class="page-head">
    <div>
        <h1>Inventario</h1>
        <p class="muted">Existencias y recetas que se descuentan al cobrar.</p>
    </div>
</section>

<section class="two-column">
    <div class="panel">
        <h2>Existencias</h2>

        <form method="post">
            <div class="inventory-grid">
                {% for item in inventario %}
                    <div>
                        <label for="stock_{{ item.ingrediente }}">{{ item.ingrediente|title }} ({{ item.unidad }})</label>
                        <input id="stock_{{ item.ingrediente }}" type="number" step="0.01" min="0" name="stock_{{ item.ingrediente }}" value="{{ item.stock }}">
                    </div>
                {% endfor %}
            </div>

            <div style="margin-top: 14px;">
                <button class="button primary" type="submit">Actualizar inventario</button>
            </div>
        </form>
    </div>

    <aside class="panel">
        <h2>Recetas de rolls</h2>

        {% for item in menu %}
            {% if recetas.get(item.id) %}
                <h3>{{ item.nombre }}</h3>
                <ul class="recipe-list">
                    {% for ingrediente, cantidad in recetas.get(item.id).items() %}
                        <li>{{ ingrediente|title }}: {{ cantidad }}</li>
                    {% endfor %}
                </ul>
            {% endif %}
        {% endfor %}
    </aside>
</section>
"""


HTML_COCINA = """
<section class="page-head">
    <div>
        <h1>Cocina / Armado</h1>
        <p class="muted">Base del rollo, preparacion, interiores y cosas que se quitan.</p>
    </div>
</section>

<section class="metrics">
    <div class="metric">
        <span>Por armar</span>
        <strong>{{ conteo_etapas.armado_pendiente }}</strong>
    </div>
    <div class="metric">
        <span>En decoracion</span>
        <strong>{{ conteo_etapas.decoracion_pendiente }}</strong>
    </div>
    <div class="metric">
        <span>Empanizado</span>
        <strong>{{ conteo_etapas.empanizado_pendiente }}</strong>
    </div>
    <div class="metric">
        <span>Pedidos</span>
        <strong>{{ pedidos|length }}</strong>
    </div>
    <div class="metric">
        <span>Hora</span>
        <strong>{{ hora }}</strong>
    </div>
</section>

{% if pedidos %}
    <div class="orders">
        {% for pedido in pedidos %}
            <article class="order-card armado {{ 'alerta' if pedido.total_items >= 4 else '' }}">
                <div class="order-head">
                    <div>
                        <h2 class="order-title">#{{ pedido.id }} - {{ pedido.cliente }}</h2>
                        <p class="muted">
                            {{ pedido.folio }} - {{ pedido.fecha }} - {{ pedido.total_items }} productos
                            {% if pedido.telefono %}- Tel: {{ pedido.telefono }}{% endif %}
                        </p>
                    </div>

                    <div class="actions">
                        <span class="timer">{{ pedido.edad_texto }}</span>
                        <span class="badge armado">Armado</span>
                    </div>
                </div>

                <ul class="work-list">
                    {% for prod in pedido.productos %}
                        <li class="work-item">
                            <div class="order-head" style="margin-bottom: 0;">
                                <div>
                                    <h3>{{ prod.producto }} x{{ prod.cantidad }}</h3>
                                    <span class="stage-chip {{ prod.etapa }}">{{ etapa_nombre(prod.etapa) }}</span>
                                    <span class="timer {{ prod.alerta_etapa }}">{{ prod.tiempo_etapa }} en armado</span>
                                </div>

                                <form action="{{ url_for('avanzar', linea_id=prod.id) }}" method="post">
                                    <button class="button primary" type="submit">Terminar armado</button>
                                </form>
                            </div>

                            <div class="work-meta">
                                <div class="work-box">
                                    <span>Preparacion</span>
                                    <strong>{{ prod.preparacion|title }}</strong>
                                </div>
                                <div class="work-box">
                                    <span>Por dentro</span>
                                    <strong>{{ prod.por_dentro or "Normal" }}</strong>
                                </div>
                                <div class="work-box">
                                    <span>Quitar</span>
                                    <strong>{{ prod.quitar or "Nada" }}</strong>
                                </div>
                                <div class="work-box">
                                    <span>Notas</span>
                                    <strong>{{ prod.notas or "Sin notas" }}</strong>
                                </div>
                            </div>
                        </li>
                    {% endfor %}
                </ul>
            </article>
        {% endfor %}
    </div>
{% else %}
    <div class="empty">No hay rollos o productos para armar.</div>
{% endif %}
"""


HTML_EMPANIZADO = """
<section class="page-head">
    <div>
        <h1>Empanizado</h1>
        <p class="muted">Solo rollos configurados como empanizados.</p>
    </div>
</section>

<section class="metrics">
    <div class="metric">
        <span>Por empanizar</span>
        <strong>{{ conteo_etapas.empanizado_pendiente }}</strong>
    </div>
    <div class="metric">
        <span>En armado</span>
        <strong>{{ conteo_etapas.armado_pendiente }}</strong>
    </div>
    <div class="metric">
        <span>Decoracion</span>
        <strong>{{ conteo_etapas.decoracion_pendiente }}</strong>
    </div>
    <div class="metric">
        <span>Hora</span>
        <strong>{{ hora }}</strong>
    </div>
</section>

{% if pedidos %}
    <div class="orders">
        {% for pedido in pedidos %}
            <article class="order-card empanizado {{ 'alerta' if pedido.total_items >= 4 else '' }}">
                <div class="order-head">
                    <div>
                        <h2 class="order-title">#{{ pedido.id }} - {{ pedido.cliente }}</h2>
                        <p class="muted">
                            {{ pedido.folio }} - {{ pedido.fecha }} - {{ pedido.total_items }} productos
                            {% if pedido.telefono %}- Tel: {{ pedido.telefono }}{% endif %}
                        </p>
                    </div>

                    <div class="actions">
                        <span class="timer">{{ pedido.edad_texto }}</span>
                        <span class="badge empanizado">Empanizado</span>
                    </div>
                </div>

                <ul class="work-list">
                    {% for prod in pedido.productos %}
                        <li class="work-item">
                            <div class="order-head" style="margin-bottom: 0;">
                                <div>
                                    <h3>{{ prod.producto }} x{{ prod.cantidad }}</h3>
                                    <span class="stage-chip {{ prod.etapa }}">{{ etapa_nombre(prod.etapa) }}</span>
                                    <span class="timer {{ prod.alerta_etapa }}">{{ prod.tiempo_etapa }} en empanizado</span>
                                </div>

                                <form action="{{ url_for('avanzar', linea_id=prod.id) }}" method="post">
                                    <button class="button primary" type="submit">Empanizado listo</button>
                                </form>
                            </div>

                            <div class="work-meta">
                                <div class="work-box">
                                    <span>Preparacion</span>
                                    <strong>{{ prod.preparacion|title }}</strong>
                                </div>
                                <div class="work-box">
                                    <span>Por dentro</span>
                                    <strong>{{ prod.por_dentro or "Normal" }}</strong>
                                </div>
                                <div class="work-box">
                                    <span>Quitar</span>
                                    <strong>{{ prod.quitar or "Nada" }}</strong>
                                </div>
                                <div class="work-box">
                                    <span>Notas</span>
                                    <strong>{{ prod.notas or "Sin notas" }}</strong>
                                </div>
                            </div>
                        </li>
                    {% endfor %}
                </ul>
            </article>
        {% endfor %}
    </div>
{% else %}
    <div class="empty">No hay rollos esperando empanizado.</div>
{% endif %}
"""


HTML_DECORACION = """
<section class="page-head">
    <div>
        <h1>Decoracion / Terminado</h1>
        <p class="muted">Toppings, salsas, tampico, ajonjoli y notas finales.</p>
    </div>
</section>

<section class="metrics">
    <div class="metric">
        <span>Por terminar</span>
        <strong>{{ conteo_etapas.decoracion_pendiente }}</strong>
    </div>
    <div class="metric">
        <span>Armado</span>
        <strong>{{ conteo_etapas.armado_pendiente }}</strong>
    </div>
    <div class="metric">
        <span>Empanizado</span>
        <strong>{{ conteo_etapas.empanizado_pendiente }}</strong>
    </div>
    <div class="metric">
        <span>Pedidos</span>
        <strong>{{ pedidos|length }}</strong>
    </div>
    <div class="metric">
        <span>Hora</span>
        <strong>{{ hora }}</strong>
    </div>
</section>

{% if pedidos %}
    <div class="orders">
        {% for pedido in pedidos %}
            <article class="order-card decoracion {{ 'alerta' if pedido.total_items >= 4 else '' }}">
                <div class="order-head">
                    <div>
                        <h2 class="order-title">#{{ pedido.id }} - {{ pedido.cliente }}</h2>
                        <p class="muted">
                            {{ pedido.folio }} - {{ pedido.fecha }} - {{ pedido.total_items }} productos
                            {% if pedido.telefono %}- Tel: {{ pedido.telefono }}{% endif %}
                        </p>
                    </div>

                    <div class="actions">
                        <span class="timer">{{ pedido.edad_texto }}</span>
                        <span class="badge decoracion">Decoracion</span>
                    </div>
                </div>

                <ul class="work-list">
                    {% for prod in pedido.productos %}
                        <li class="work-item">
                            <div class="order-head" style="margin-bottom: 0;">
                                <div>
                                    <h3>{{ prod.producto }} x{{ prod.cantidad }}</h3>
                                    <span class="stage-chip {{ prod.etapa }}">{{ etapa_nombre(prod.etapa) }}</span>
                                    <span class="timer {{ prod.alerta_etapa }}">{{ prod.tiempo_etapa }} en decoracion</span>
                                </div>

                                <form action="{{ url_for('avanzar', linea_id=prod.id) }}" method="post">
                                    <button class="button ready" type="submit">Listo</button>
                                </form>
                            </div>

                            <div class="work-meta">
                                <div class="work-box">
                                    <span>Terminado</span>
                                    <strong>{{ prod.terminado or "Sin topping especial" }}</strong>
                                </div>
                                <div class="work-box">
                                    <span>Extras</span>
                                    <strong>{{ prod.extras or "Sin extras" }}</strong>
                                </div>
                                <div class="work-box">
                                    <span>Preparacion</span>
                                    <strong>{{ prod.preparacion|title }}</strong>
                                </div>
                                <div class="work-box">
                                    <span>Notas</span>
                                    <strong>{{ prod.notas or "Sin notas" }}</strong>
                                </div>
                            </div>
                        </li>
                    {% endfor %}
                </ul>
            </article>
        {% endfor %}
    </div>
{% else %}
    <div class="empty">No hay rollos esperando decoracion.</div>
{% endif %}
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip().lower()
        password = request.form.get("password", "")
        datos = USUARIOS.get(usuario)

        bloqueo = segundos_bloqueo_login(usuario)
        if bloqueo:
            minutos = max(1, (bloqueo + 59) // 60)
            flash(f"Demasiados intentos. Espera {minutos} min e intenta de nuevo.", "error")
            return render_page("Login - Black Roll Sushi", "login", HTML_LOGIN)

        if datos and password_usuario_valida(datos, password):
            session.clear()
            session.permanent = True
            session["usuario"] = datos["nombre"]
            session["rol"] = datos["rol"]
            limpiar_intentos_login(usuario)

            siguiente = request.args.get("next")
            if siguiente and siguiente.startswith("/") and not siguiente.startswith("//"):
                return redirect(siguiente)
            return redirect(destino_por_rol())

        registrar_login_fallido(usuario)
        flash("Usuario o contrasena incorrectos.", "error")

    return render_page("Login - Black Roll Sushi", "login", HTML_LOGIN)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@requiere_roles("caja", "administrador")
def index():
    if request.args.get("nuevo"):
        session.pop("pedido_activo_id", None)
    pedido_activo_id = request.args.get("pedido_id", type=int)
    contexto = contexto_caja(pedido_activo_id)

    if quiere_json():
        return respuesta_caja_ajax(contexto["pedido_activo_id"])

    return render_page(
        "Caja - Black Roll Sushi",
        "caja",
        HTML_CAJA,
        **contexto,
    )


@app.route("/pedido/agregar", methods=["POST"])
@requiere_roles("caja", "administrador")
def agregar_producto():
    cliente = request.form.get("cliente", "").strip()
    telefono = request.form.get("telefono", "").strip()
    producto_id = request.form.get("producto_id", "").strip()
    pedido_id = request.form.get("pedido_id", "").strip()
    producto = buscar_producto(producto_id)
    preparacion = request.form.get("preparacion", "natural")
    if preparacion not in {item["id"] for item in PREPARACIONES}:
        preparacion = "natural"

    modificadores = {
        "preparacion": preparacion,
        "por_dentro": combinar_opciones(
            request.form.getlist("por_dentro_opciones"),
            request.form.get("por_dentro", ""),
        ),
        "quitar": combinar_opciones(request.form.getlist("quitar"), request.form.get("quitar_extra", "")),
        "extras": request.form.get("extras", "").strip(),
        "terminado": combinar_opciones(request.form.getlist("terminado")),
        "notas": request.form.get("notas", "").strip(),
    }

    if producto is None:
        if quiere_json():
            return respuesta_caja_ajax(session.get("pedido_activo_id"), "Producto no valido.", "error", 400)
        flash("Producto no valido.", "error")
        return redirect(url_for("index"))

    conn = conectar_db()

    if pedido_id:
        pedido = obtener_pedido(conn, pedido_id)
        if pedido is None:
            conn.close()
            if quiere_json():
                return respuesta_caja_ajax(session.get("pedido_activo_id"), "El pedido seleccionado ya no existe.", "error", 404)
            flash("El pedido seleccionado ya no existe.", "error")
            return redirect(url_for("index"))
        pedido_id = pedido["id"]
        if telefono and not pedido["telefono"]:
            conn.execute("""
                UPDATE pedidos
                SET telefono = ?
                WHERE id = ?
            """, (telefono, pedido_id))
    else:
        if not cliente:
            conn.close()
            if quiere_json():
                return respuesta_caja_ajax(session.get("pedido_activo_id"), "Escribe el cliente para crear un pedido nuevo.", "error", 400)
            flash("Escribe el cliente para crear un pedido nuevo.", "error")
            return redirect(url_for("index"))

        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO pedidos (cliente, telefono, estado, total, fecha)
            VALUES (?, ?, 'pendiente', 0, ?)
        """, (cliente, telefono, fecha))
        pedido_id = cursor.lastrowid

    agregar_producto_a_pedido(conn, pedido_id, producto, modificadores)
    conn.commit()
    conn.close()

    session["pedido_activo_id"] = pedido_id
    if quiere_json():
        return respuesta_caja_ajax(pedido_id, f"{producto['nombre']} agregado al pedido #{pedido_id}.")
    flash(f"{producto['nombre']} agregado al pedido #{pedido_id}.", "success")
    return redirect(url_for("index", pedido_id=pedido_id))


@app.route("/pedido/<int:pedido_id>/producto/<int:linea_id>/sumar", methods=["POST"])
@requiere_roles("caja", "administrador")
def sumar_producto(pedido_id, linea_id):
    conn = conectar_db()
    linea = conn.execute("""
        SELECT *
        FROM pedido_productos
        WHERE id = ? AND pedido_id = ?
    """, (linea_id, pedido_id)).fetchone()

    if linea and linea["etapa"] == "armado_pendiente":
        conn.execute("""
            UPDATE pedido_productos
            SET cantidad = cantidad + 1
            WHERE id = ?
        """, (linea_id,))
        sincronizar_historial_abierto(conn, linea_id)
        recalcular_total(conn, pedido_id)
        actualizar_estado_pedido(conn, pedido_id)
        conn.commit()
        session["pedido_activo_id"] = pedido_id
        mensaje = "+1 igual agregado."
        categoria = "success"
    else:
        mensaje = "No se pudo duplicar este producto."
        categoria = "error"

    conn.close()
    if quiere_json():
        return respuesta_caja_ajax(pedido_id, mensaje, categoria, 200 if categoria == "success" else 400)
    return redirect(url_for("index", pedido_id=pedido_id))


@app.route("/pedido/<int:pedido_id>/producto/<int:linea_id>/restar", methods=["POST"])
@requiere_roles("caja", "administrador")
def restar_producto(pedido_id, linea_id):
    conn = conectar_db()
    linea = conn.execute("""
        SELECT *
        FROM pedido_productos
        WHERE id = ? AND pedido_id = ?
    """, (linea_id, pedido_id)).fetchone()

    mensaje = "Cantidad actualizada."
    categoria = "success"

    if linea and linea["etapa"] == "armado_pendiente":
        if linea["cantidad"] > 1:
            conn.execute("""
                UPDATE pedido_productos
                SET cantidad = cantidad - 1
                WHERE id = ?
            """, (linea_id,))
            sincronizar_historial_abierto(conn, linea_id)
            recalcular_total(conn, pedido_id)
            actualizar_estado_pedido(conn, pedido_id)
        else:
            cerrar_historial_abierto_linea(conn, linea_id)
            conn.execute("DELETE FROM pedido_productos WHERE id = ?", (linea_id,))
            restantes = obtener_productos_pedido(conn, pedido_id)
            if restantes:
                recalcular_total(conn, pedido_id)
                actualizar_estado_pedido(conn, pedido_id)
                session["pedido_activo_id"] = pedido_id
            else:
                borrar_pedido(conn, pedido_id)
                if session.get("pedido_activo_id") == pedido_id:
                    session.pop("pedido_activo_id", None)
                flash("Pedido cancelado porque quedo sin productos.", "info")
                mensaje = "Pedido cancelado porque quedo sin productos."
                categoria = "info"

        conn.commit()
    else:
        mensaje = "No se pudo restar este producto."
        categoria = "error"

    conn.close()
    if quiere_json():
        activo = pedido_id if session.get("pedido_activo_id") == pedido_id else None
        return respuesta_caja_ajax(activo, mensaje, categoria, 200 if categoria != "error" else 400)
    if session.get("pedido_activo_id") == pedido_id:
        return redirect(url_for("index", pedido_id=pedido_id))
    return redirect(url_for("index"))


@app.route("/pedido/<int:pedido_id>/producto/<int:linea_id>/eliminar", methods=["POST"])
@requiere_roles("caja", "administrador")
def eliminar_producto(pedido_id, linea_id):
    conn = conectar_db()
    cerrar_historial_abierto_linea(conn, linea_id)
    conn.execute("""
        DELETE FROM pedido_productos
        WHERE id = ? AND pedido_id = ?
    """, (linea_id, pedido_id))

    restantes = obtener_productos_pedido(conn, pedido_id)
    if restantes:
        recalcular_total(conn, pedido_id)
        actualizar_estado_pedido(conn, pedido_id)
        session["pedido_activo_id"] = pedido_id
        flash("Producto eliminado del pedido.", "success")
        mensaje = "Producto eliminado del pedido."
        categoria = "success"
    else:
        borrar_pedido(conn, pedido_id)
        if session.get("pedido_activo_id") == pedido_id:
            session.pop("pedido_activo_id", None)
        flash("Pedido cancelado porque quedo sin productos.", "info")
        mensaje = "Pedido cancelado porque quedo sin productos."
        categoria = "info"

    conn.commit()
    conn.close()
    if quiere_json():
        activo = pedido_id if session.get("pedido_activo_id") == pedido_id else None
        return respuesta_caja_ajax(activo, mensaje, categoria)
    if session.get("pedido_activo_id") == pedido_id:
        return redirect(url_for("index", pedido_id=pedido_id))
    return redirect(url_for("index"))


@app.route("/producto/<int:linea_id>/editar", methods=["GET", "POST"])
@requiere_roles("caja", "administrador")
def editar_producto(linea_id):
    conn = conectar_db()
    producto = conn.execute("""
        SELECT *
        FROM pedido_productos
        WHERE id = ?
    """, (linea_id,)).fetchone()

    if producto is None:
        conn.close()
        flash("Producto no encontrado.", "error")
        return redirect(url_for("index"))

    pedido = obtener_pedido(conn, producto["pedido_id"])

    if request.method == "POST":
        preparacion = request.form.get("preparacion", "natural")
        if preparacion not in {item["id"] for item in PREPARACIONES}:
            preparacion = "natural"
        nueva_etapa = producto["etapa"]
        producto_menu = buscar_producto(producto["producto_id"])

        if producto_menu and producto_requiere_decoracion(producto_menu):
            if producto["etapa"] == "empanizado_pendiente" and preparacion != "empanizado":
                nueva_etapa = "decoracion_pendiente"
            elif producto["etapa"] == "decoracion_pendiente" and preparacion == "empanizado":
                nueva_etapa = "empanizado_pendiente"

        conn.execute("""
            UPDATE pedido_productos
            SET preparacion = ?,
                por_dentro = ?,
                quitar = ?,
                extras = ?,
                terminado = ?,
                notas = ?
            WHERE id = ?
        """, (
            preparacion,
            combinar_opciones(request.form.getlist("por_dentro_opciones"), request.form.get("por_dentro", "")),
            combinar_opciones(request.form.getlist("quitar"), request.form.get("quitar_extra", "")),
            request.form.get("extras", "").strip(),
            combinar_opciones(request.form.getlist("terminado")),
            request.form.get("notas", "").strip(),
            linea_id,
        ))
        if nueva_etapa != producto["etapa"]:
            cambiar_etapa_producto(conn, linea_id, nueva_etapa)
        else:
            sincronizar_historial_abierto(conn, linea_id)
        actualizar_estado_pedido(conn, producto["pedido_id"])
        conn.commit()
        conn.close()

        session["pedido_activo_id"] = producto["pedido_id"]
        flash("Modificadores actualizados.", "success")
        return redirect(url_for("index", pedido_id=producto["pedido_id"]))

    conn.close()
    return render_page(
        "Editar producto - Black Roll Sushi",
        "caja",
        HTML_EDITAR_PRODUCTO,
        pedido=pedido,
        producto=producto,
    )


@app.route("/cancelar/<int:pedido_id>", methods=["POST"])
@requiere_roles("caja", "administrador")
def cancelar_pedido(pedido_id):
    conn = conectar_db()
    borrar_pedido(conn, pedido_id)
    conn.commit()
    conn.close()

    if session.get("pedido_activo_id") == pedido_id:
        session.pop("pedido_activo_id", None)
    flash(f"Pedido #{pedido_id} cancelado.", "info")
    return redirect(url_for("index"))


@app.route("/cocina")
@requiere_roles("cocina", "administrador")
def cocina():
    pedidos = obtener_pedidos_por_etapa("armado_pendiente")

    return render_page(
        "Armado - Black Roll Sushi",
        "cocina",
        HTML_COCINA,
        pedidos=pedidos,
        conteo_etapas=contar_lineas_por_etapa(),
        hora=datetime.now().strftime("%H:%M"),
    )


@app.route("/decoracion")
@requiere_roles("decoracion", "administrador")
def decoracion():
    pedidos = obtener_pedidos_por_etapa("decoracion_pendiente")

    return render_page(
        "Decoracion - Black Roll Sushi",
        "decoracion",
        HTML_DECORACION,
        pedidos=pedidos,
        conteo_etapas=contar_lineas_por_etapa(),
        hora=datetime.now().strftime("%H:%M"),
    )


@app.route("/empanizado")
@requiere_roles("empanizado", "administrador")
def empanizado():
    pedidos = obtener_pedidos_por_etapa("empanizado_pendiente")

    return render_page(
        "Empanizado - Black Roll Sushi",
        "empanizado",
        HTML_EMPANIZADO,
        pedidos=pedidos,
        conteo_etapas=contar_lineas_por_etapa(),
        hora=datetime.now().strftime("%H:%M"),
    )


@app.post("/avanzar/<int:linea_id>")
@app.route("/avanzar_etapa/<int:linea_id>", methods=["POST"], endpoint="avanzar_etapa")
@requiere_roles("cocina", "empanizado", "decoracion", "administrador")
def avanzar(linea_id):
    conn = conectar_db()
    linea = conn.execute("""
        SELECT *
        FROM pedido_productos
        WHERE id = ?
    """, (linea_id,)).fetchone()

    if linea is None:
        conn.close()
        flash("Producto no encontrado.", "error")
        return redirect(destino_por_rol())

    if not rol_puede_avanzar(linea["etapa"]):
        conn.close()
        flash("Este producto no corresponde a tu estacion.", "error")
        return redirect(destino_por_rol())

    etapa_anterior = linea["etapa"]
    nueva_etapa = siguiente_etapa_producto(linea)

    cambiar_etapa_producto(conn, linea_id, nueva_etapa)
    actualizar_estado_pedido(conn, linea["pedido_id"])

    conn.commit()
    conn.close()

    flash(
        f"{linea['producto']} avanzo de {etapa_nombre(etapa_anterior)} a {etapa_nombre(nueva_etapa)}.",
        "success",
    )
    destino = request.referrer or destino_por_rol()
    return redirect(destino)


@app.route("/listo/<int:pedido_id>", methods=["POST"])
@requiere_roles("administrador")
def marcar_listo(pedido_id):
    conn = conectar_db()
    productos = obtener_productos_pedido(conn, pedido_id)
    for producto in productos:
        cambiar_etapa_producto(conn, producto["id"], "listo")
    actualizar_estado_pedido(conn, pedido_id)
    conn.commit()
    conn.close()

    destino = request.referrer or destino_por_rol()
    return redirect(destino)


@app.route("/cobrar/<int:pedido_id>", methods=["POST"])
@requiere_roles("caja", "administrador")
def cobrar(pedido_id):
    metodo_pago = request.form.get("metodo_pago", "efectivo")
    metodos_validos = {metodo["id"] for metodo in METODOS_PAGO}

    if metodo_pago not in metodos_validos:
        flash("Metodo de pago no valido.", "error")
        return redirect(url_for("index"))

    conn = conectar_db()
    pedido = obtener_pedido(conn, pedido_id)

    if pedido is None:
        conn.close()
        flash("El pedido ya no existe.", "error")
        return redirect(url_for("index"))

    productos = obtener_productos_pedido(conn, pedido_id)
    total = recalcular_total(conn, pedido_id)

    if not productos or total <= 0:
        conn.close()
        flash("No se puede cobrar un pedido sin productos.", "error")
        return redirect(url_for("index"))

    if any(producto["etapa"] != "listo" for producto in productos):
        conn.close()
        flash("Este pedido todavia no esta listo para cobrar.", "error")
        return redirect(url_for("index", pedido_id=pedido_id))

    faltantes = validar_inventario(conn, productos)
    if faltantes:
        conn.close()
        detalle = ", ".join(f"{item['ingrediente']} ({item['faltan']} {item['unidad']})" for item in faltantes)
        flash(f"Inventario insuficiente: {detalle}.", "error")
        return redirect(url_for("index"))

    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    folio = folio_pedido(pedido_id)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO ventas (folio, cliente, telefono, total, metodo_pago, fecha)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (folio, pedido["cliente"], pedido["telefono"], total, metodo_pago, fecha))
    venta_id = cursor.lastrowid

    for producto in productos:
        cursor.execute("""
            INSERT INTO venta_productos (
                venta_id, producto, precio, cantidad,
                preparacion, por_dentro, quitar, extras, terminado, notas
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            venta_id,
            producto["producto"],
            producto["precio"],
            producto["cantidad"],
            producto["preparacion"],
            producto["por_dentro"],
            producto["quitar"],
            producto["extras"],
            producto["terminado"],
            producto["notas"],
        ))

    descontar_inventario(conn, productos)
    borrar_pedido(conn, pedido_id)

    conn.commit()
    conn.close()

    if session.get("pedido_activo_id") == pedido_id:
        session.pop("pedido_activo_id", None)
    flash(f"Pedido {folio} cobrado con {metodo_nombre(metodo_pago).lower()}.", "success")
    return redirect(url_for("ticket", venta_id=venta_id))


@app.route("/ventas")
@requiere_roles("caja", "administrador")
def ventas_historial():
    fecha = request.args.get("fecha") or datetime.now().strftime("%Y-%m-%d")
    ventas_dia, total_ventas, total_ingresos, totales_metodo, fecha = obtener_ventas(fecha)

    return render_page(
        "Ventas - Black Roll Sushi",
        "ventas",
        HTML_VENTAS,
        ventas=ventas_dia,
        total_ventas=total_ventas,
        total_ingresos=total_ingresos,
        totales_metodo=totales_metodo,
        fecha=fecha,
    )


@app.route("/negocio")
@requiere_roles("administrador")
def negocio():
    fecha = request.args.get("fecha") or datetime.now().strftime("%Y-%m-%d")
    datos = obtener_dashboard_negocio(fecha)

    return render_page(
        "Negocio - Black Roll Sushi",
        "negocio",
        HTML_NEGOCIO,
        **datos,
    )


@app.route("/respaldar", methods=["POST"])
@requiere_roles("administrador")
def respaldar():
    respaldo = crear_respaldo_db()
    return send_file(
        respaldo,
        as_attachment=True,
        download_name=respaldo.name,
        mimetype="application/octet-stream",
    )


@app.route("/ventas/exportar")
@requiere_roles("caja", "administrador")
def exportar_ventas():
    fecha = request.args.get("fecha") or datetime.now().strftime("%Y-%m-%d")
    contenido = exportar_ventas_csv(fecha)
    nombre = f"ventas-{fecha}.csv"
    return Response(
        contenido,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={nombre}"},
    )


@app.route("/produccion")
@requiere_roles("administrador")
def produccion():
    fecha = request.args.get("fecha") or datetime.now().strftime("%Y-%m-%d")
    datos = obtener_historial_produccion(fecha)

    return render_page(
        "Produccion - Black Roll Sushi",
        "produccion",
        HTML_PRODUCCION,
        **datos,
    )


@app.route("/ticket/<int:venta_id>")
@requiere_roles("caja", "administrador")
def ticket(venta_id):
    venta, productos = obtener_venta(venta_id)

    if venta is None:
        flash("Ticket no encontrado.", "error")
        return redirect(url_for("ventas_historial"))

    return render_page(
        f"Ticket {venta['folio']} - Black Roll Sushi",
        "ventas",
        HTML_TICKET,
        venta=venta,
        productos=productos,
    )


@app.route("/inventario", methods=["GET", "POST"])
@requiere_roles("administrador")
def inventario():
    if request.method == "POST":
        conn = conectar_db()
        inventario_db = conn.execute("SELECT ingrediente FROM inventario").fetchall()

        for item in inventario_db:
            campo = f"stock_{item['ingrediente']}"
            valor = request.form.get(campo, "0")
            try:
                stock = max(float(valor), 0)
            except ValueError:
                stock = 0

            conn.execute("""
                UPDATE inventario
                SET stock = ?
                WHERE ingrediente = ?
            """, (stock, item["ingrediente"]))

        conn.commit()
        conn.close()
        flash("Inventario actualizado.", "success")
        return redirect(url_for("inventario"))

    return render_page(
        "Inventario - Black Roll Sushi",
        "inventario",
        HTML_INVENTARIO,
        inventario=obtener_inventario(),
        recetas=RECETAS,
    )


crear_tablas()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, use_reloader=False, host="0.0.0.0", port=port)
