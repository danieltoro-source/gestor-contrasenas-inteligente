"Boveda cifrada"

import base64
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CARPETA_PROYECTO = Path(__file__).resolve().parent.parent
RUTA_BOVEDA = CARPETA_PROYECTO / "data" / "boveda.db"

INTERACIONES = 600_000
TEXTO_VERIFICADOR = b"boveda_ok"

def derivar_llave(clave_maestra, sal):
    "convierte la clave maestra en llave cifrada con PBKDF2HMAC"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal, iterations=INTERACIONES)
    llave = kdf.derive(clave_maestra.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(llave))

def conectar(ruta=RUTA_BOVEDA):
    "abre la base de datos y crea las tablas si no existen"
    conexion = sqlite3.connect(ruta)
    conexion.execute("CREATE TABLE IF NOT EXISTS configuracion (sal BLOB, verificacion BLOB)")
    conexion.execute(
        "CREATE TABLE IF NOT EXISTS credenciales ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "sitio BLOB, usuario BLOB, contrasena BLOB, creada TEXT)"
    )
    return conexion

def existe_boveda(ruta=RUTA_BOVEDA):
    "ya se creo la boveda con su clave maestra?"
    if not Path(ruta).exists():
        return False
    with conectar(ruta) as conexion:
        return conexion.execute("SELECT COUNT(*) FROM configuracion").fetchone()[0] > 0

def crear_boveda(clave_maestra, ruta=RUTA_BOVEDA):
    "crear la boveda"
    sal = os.urandom(16)
    fernet = derivar_llave(clave_maestra, sal)
    verificador = fernet.encrypt(TEXTO_VERIFICADOR)
    with conectar(ruta) as conexion:
        conexion.execute("INSERT INTO configuracion VALUES (?, ?)", (sal, verificador))
    return fernet

def abrir_boveda(clave_maestra, ruta=RUTA_BOVEDA):
    "devuelve la llave si la clave es correcta sino lanza ValueError"
    with conectar(ruta) as conexion:
        sal, verificador = conexion.execute("SELECT sal, verificacion FROM configuracion").fetchone()
    fernet = derivar_llave(clave_maestra, sal)
    try:
        fernet.decrypt(verificador)
    except InvalidToken:
        raise ValueError("Clave maestra incorrecta")
    return fernet

def agregar_credencial(fernet, sitio, usuario, contrasena, ruta=RUTA_BOVEDA):
    "cifra y guarda una credencial"
    datos = [fernet.encrypt(texto.encode("utf-8")) for texto in (sitio, usuario, contrasena)]
    creada = datetime.now().strftime("%Y-%m-%d %H:%M")
    with conectar(ruta) as conexion:
        conexion.execute(
            "INSERT INTO credenciales (sitio, usuario, contrasena, creada) VALUES (?, ?, ?, ?)",
            (*datos, creada),
        )

def listar_credenciales(fernet, ruta=RUTA_BOVEDA):
    "devuelve todas las credenciales descifradas, como una lista"
    with conectar(ruta) as conexion:
        filas = conexion.execute(
            "SELECT id, sitio, usuario, contrasena, creada FROM credenciales"
        ).fetchall()
    return [
        {
            "id": id_,
            "sitio": fernet.decrypt(sitio).decode("utf-8"),
            "usuario": fernet.decrypt(usuario).decode("utf-8"),
            "contrasena": fernet.decrypt(contrasena).decode("utf-8"),
            "creada": creada,
        }
        for id_, sitio, usuario, contrasena, creada in filas
    ]


def eliminar_credencial(id_credencial, ruta=RUTA_BOVEDA):
    "borra una credencial por su id"
    with conectar(ruta) as conexion:
        conexion.execute("DELETE FROM credenciales WHERE id = ?", (id_credencial,))