"""Consulta Pwned Passwords con k-anonimato: la contraseña nunca sale completa del equipo."""

import hashlib

import requests

URL_API = "https://api.pwnedpasswords.com/range/"


def hash_sha1(contrasena):
    """Devuelve el hash SHA-1 de la contraseña, en mayúsculas."""
    return hashlib.sha1(contrasena.encode("utf-8")).hexdigest().upper()


def veces_filtrada(contrasena, tiempo_maximo=5):
    """Cuántas veces aparece la contraseña en filtraciones conocidas.

    Devuelve un número (0 = no aparece) o None si no se pudo consultar.
    """
    sha1 = hash_sha1(contrasena)
    prefijo, sufijo = sha1[:5], sha1[5:]

    try:
        respuesta = requests.get(
            URL_API + prefijo,
            headers={"Add-Padding": "true", "User-Agent": "gestor-contrasenas-etitc"},
            timeout=tiempo_maximo,
        )
        respuesta.raise_for_status()
    except requests.RequestException:
        return None

    for linea in respuesta.text.splitlines():
        sufijo_recibido, conteo = linea.split(":")
        if sufijo_recibido == sufijo:
            return int(conteo)
    return 0