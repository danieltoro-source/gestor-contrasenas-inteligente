"""Generador de contraseñas seguras con la librería secrets."""

import secrets
import string

SIMBOLOS = "!@#$%&*?-_+="

PALABRAS = [
    "nube", "cactus", "tambor", "lago", "cometa", "piano", "volcan", "tigre",
    "faro", "brujula", "canela", "dragon", "espejo", "fresa", "galaxia", "hielo",
    "iguana", "jirafa", "koala", "linterna", "mango", "naranja", "oceano", "pinguino",
    "quimera", "robot", "sandia", "tortuga", "unicornio", "violin", "yate", "zorro",
    "ancla", "bosque", "cabana", "delfin", "escalera", "flauta", "girasol", "hormiga",
    "isla", "jardin", "lampara", "montana", "nieve", "orquidea", "palmera", "queso",
    "relampago", "sombrero", "trompeta", "uva", "ventana", "abeja", "ballena", "cereza",
    "diamante", "estrella", "foca", "globo", "hamaca", "iman", "jaguar", "kiwi",
    "limon", "mariposa", "nutria", "ola", "pradera", "rio", "selva", "tren",
    "valle", "arena", "bicicleta", "castillo", "desierto", "eclipse", "fuego", "granizo",
    "hoja", "invierno", "llama", "maleta", "nido", "oso", "pez", "puente",
    "raton", "sol", "trueno", "viento", "aguila", "buho", "colibri", "dado",
    "elefante", "fogata", "guitarra", "helado", "lobo", "luna", "mapache", "mochila",
    "panda", "pirata", "pulpo", "roca", "semilla", "tiburon", "tucan", "vela",
    "zapato", "arbol", "barco", "camello", "cascada", "conejo", "cuervo", "lirio",
    "nopal", "perro", "planeta", "saturno", "tetera", "trigo", "volantin", "yuca",
]


def generar_aleatoria(longitud=16):
    """Contraseña al azar con minúsculas, mayúsculas, dígitos y símbolos."""
    grupos = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SIMBOLOS]
    todos = "".join(grupos)
    while True:
        contrasena = "".join(secrets.choice(todos) for _ in range(longitud))
        if all(any(c in grupo for c in contrasena) for grupo in grupos):
            return contrasena


def generar_frase(cantidad_palabras=5):
    """Frase fácil de recordar: palabras al azar + un número, separadas por guiones."""
    palabras = [secrets.choice(PALABRAS).capitalize() for _ in range(cantidad_palabras)]
    numero = secrets.randbelow(90) + 10
    return "-".join(palabras) + f"-{numero}"