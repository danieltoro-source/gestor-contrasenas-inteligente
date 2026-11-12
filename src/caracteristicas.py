import math
import re 
from collections import Counter

import pandas as pd
TAMANO_GRUPO = {"minusculas": 26, "mayusculas": 26, "digitos": 10, "simbolos": 33}

def entropia_shannon(texto):
    if not texto:
        return 0.0
    n = len(texto)
    conteo = Counter(texto)
    por_caracter = -sum((c / n) * math.log2(c / n) for c in conteo.values())
    return abs(por_caracter * n)

def extraer_caracteristicas(contrasenas, diccionario_comunes=None):

    s = pd.Series(contrasenas, dtype="str").reset_index(drop=True)
    c = pd.DataFrame(index=s.index)

#conteo basico
    c["longitud"] = s.str.len()
    c["n_minusculas"] = s.str.count(r"[a-z]")
    c["n_mayusculas"] = s.str.count(r"[A-Z]")
    c["n_digitos"] = s.str.count(r"[0-9]")
    c["n_simbolos"] = c["longitud"] - c["n_minusculas"] - c["n_mayusculas"] - c["n_digitos"]

    tiene = c[["n_minusculas", "n_mayusculas", "n_digitos", "n_simbolos"]] > 0
    c["tipos_distintos"] = tiene.sum(axis=1)

    grupo = (
        tiene["n_minusculas"] * TAMANO_GRUPO["minusculas"]
        + tiene["n_mayusculas"] * TAMANO_GRUPO["mayusculas"]
        + tiene["n_digitos"] * TAMANO_GRUPO["digitos"]
        + tiene["n_simbolos"] * TAMANO_GRUPO["simbolos"]
    )

    c["entropia_reglas"] = c["longitud"] * grupo.clip(lower=1).apply(math.log2)
    c["entropia_shannon"] = s.apply(entropia_shannon)

    c["proporcion_unicos"] = s.apply(lambda t: len(set(t)) / len(t) if t else 0)

    c["termina_en_numero"] = s.str.contains(r"[0-9]$").astype(int)
    c["empieza_mayuscula"] = s.str.contains(r"^[A-Z]").astype(int)
    c["letras_luego_numeros"] = s.str.fullmatch(r"[a-zA-Z]+[0-9]+").astype(int)
    c["contiene_anio"] = s.str.contains(r"(?:19[5-9][0-9]|20[0-2][0-9])").astype(int)
    c["caracter_repetido"] = s.apply(lambda t: bool(re.search(r"(.)\1\1", t))).astype(int)
    c["secuencia_comun"] = s.str.contains(r"123|abc|qwe|asd|zxc", case=False).astype(int)

    if diccionario_comunes is not None:
        c["en_rockyou"] = s.isin(diccionario_comunes).astype(int)
    return c
