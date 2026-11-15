"""Motor de riesgo: combina cuatro fuentes en un puntaje de 0 a 100."""

import math
from pathlib import Path

import joblib
import pandas as pd
from zxcvbn import zxcvbn

from src.caracteristicas import extraer_caracteristicas
from src.filtraciones import veces_filtrada

CARPETA_PROYECTO = Path(__file__).resolve().parent.parent
RUTA_MODELO = CARPETA_PROYECTO / "models" / "modelo_vulnerabilidad.joblib"
RUTA_ROCKYOU = CARPETA_PROYECTO / "data" / "processed" / "rockyou_limpio.parquet"

PESOS = {"filtraciones": 0.35, "zxcvbn": 0.30, "modelo": 0.25, "rockyou": 0.10}
PISO_SI_FILTRADA = 70
PISO_SI_PATRON = 30
LONGITUD_SEGURA = 12


def cargar_recursos(cantidad_comunes=1_000_000):
    """Carga una sola vez el modelo y la lista de contraseñas comunes."""
    paquete = joblib.load(RUTA_MODELO)
    rockyou = pd.read_parquet(RUTA_ROCKYOU, columns=["password"])
    comunes = set(rockyou["password"].head(cantidad_comunes))
    return {"modelo": paquete["modelo"], "columnas": paquete["columnas"], "comunes": comunes}


def nivel_de_riesgo(puntaje):
    """Traduce el puntaje a un nivel del semáforo."""
    if puntaje >= 60:
        return "Alto"
    if puntaje >= 30:
        return "Medio"
    return "Bajo"


def calcular_riesgo(contrasena, recursos, consultar_filtraciones=True):
    """Analiza una contraseña y devuelve su puntaje de riesgo y las razones."""
    veces = veces_filtrada(contrasena) if consultar_filtraciones else None
    analisis_zxcvbn = zxcvbn(contrasena[:100])
    X = extraer_caracteristicas([contrasena])[recursos["columnas"]]
    probabilidad = float(recursos["modelo"].predict_proba(X)[0, 1])
    en_rockyou = contrasena in recursos["comunes"]

    componentes = {
        "filtraciones": 0.0 if not veces else min(1.0, math.log10(veces + 1) / 5),
        "zxcvbn": 1 - analisis_zxcvbn["score"] / 4,
        "modelo": probabilidad,
        "rockyou": 1.0 if en_rockyou else 0.0,
    }

    puntaje = 100 * sum(PESOS[nombre] * valor for nombre, valor in componentes.items())
    patron_predecible = (
        (X["letras_luego_numeros"].iloc[0] == 1 or X["contiene_anio"].iloc[0] == 1)
        and X["longitud"].iloc[0] < LONGITUD_SEGURA
    )
    if veces:
        puntaje = max(puntaje, PISO_SI_FILTRADA)
    if patron_predecible:
        puntaje = max(puntaje, PISO_SI_PATRON)
    puntaje = round(puntaje)

    razones = []
    if veces:
        razones.append(f"Apareció {veces:,} veces en filtraciones reales.")
    elif veces is None:
        razones.append("No se pudo consultar Pwned Passwords (sin conexión).")
    if en_rockyou:
        razones.append("Está entre el millón de contraseñas más usadas (RockYou).")
    if analisis_zxcvbn["score"] <= 1:
        razones.append("zxcvbn detecta patrones que la hacen fácil de adivinar.")
    if patron_predecible:
        razones.append("Es corta y sigue un patrón predecible (palabra + números o un año).")
    if probabilidad >= 0.5:
        razones.append(f"El modelo le da {probabilidad:.0%} de probabilidad de ser de las que se filtran.")
    if not razones:
        razones.append("No se detectaron riesgos importantes.")

    return {
        "puntaje": puntaje,
        "nivel": nivel_de_riesgo(puntaje),
        "veces_filtrada": veces,
        "en_rockyou": en_rockyou,
        "zxcvbn_score": analisis_zxcvbn["score"],
        "tiempo_para_adivinarla": analisis_zxcvbn["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "probabilidad_modelo": probabilidad,
        "componentes": componentes,
        "razones": razones,
    }
    