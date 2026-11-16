"""App del Gestor de Contraseñas Inteligente (Streamlit)."""

import pandas as pd
import streamlit as st

from src import boveda
from src.generador import generar_aleatoria, generar_frase
from src.riesgo import calcular_riesgo, cargar_recursos

st.set_page_config(page_title="Gestor de Contraseñas", page_icon="🔐", layout="centered")

LONGITUD_MINIMA_MAESTRA = 12

SEMAFORO = {"Bajo": "🟢", "Medio": "🟡", "Alto": "🔴"}

CONSEJOS = {
    "Alto": "Cámbiala ya. Usa una frase larga de 4 palabras o más, o genera una en la pestaña Analizar.",
    "Medio": "Mejórala: hazla más larga y evita años o números al final.",
    "Bajo": "Bien. Solo no la repitas en otros sitios.",
}

TRADUCCIONES = {
    "less than a second": "menos de un segundo",
    "centuries": "siglos",
    "seconds": "segundos", "second": "segundo",
    "minutes": "minutos", "minute": "minuto",
    "hours": "horas", "hour": "hora",
    "days": "días", "day": "día",
    "months": "meses", "month": "mes",
    "years": "años", "year": "año",
}


@st.cache_resource(show_spinner="Cargando el modelo y RockYou (solo la primera vez)...")
def obtener_recursos():
    """Carga el modelo y las contraseñas comunes una sola vez."""
    return cargar_recursos()


def analizar(contrasena):
    """Calcula el riesgo y lo recuerda durante la sesión, para no repetir consultas."""
    memoria = st.session_state.setdefault("analisis", {})
    if contrasena not in memoria:
        memoria[contrasena] = calcular_riesgo(contrasena, obtener_recursos())
    return memoria[contrasena]


def traducir_tiempo(texto):
    """Traduce al español el tiempo que da zxcvbn (viene en inglés)."""
    for ingles, espanol in TRADUCCIONES.items():
        texto = texto.replace(ingles, espanol)
    return texto


def mostrar_resultado(resultado):
    """Dibuja el puntaje, el semáforo, el consejo y las razones."""
    nivel = resultado["nivel"]
    col1, col2, col3 = st.columns(3)
    col1.metric("Riesgo", f"{resultado['puntaje']} / 100")
    col2.metric("Nivel", f"{SEMAFORO[nivel]} {nivel}")
    veces = resultado["veces_filtrada"]
    col3.metric("Veces filtrada", "Sin conexión" if veces is None else f"{veces:,}")
    st.progress(resultado["puntaje"] / 100)
    st.write(f"⏱️ Tiempo estimado para adivinarla: **{traducir_tiempo(resultado['tiempo_para_adivinarla'])}**")
    st.write("**Por qué:**")
    for razon in resultado["razones"]:
        st.write(f"- {razon}")
    if nivel == "Alto":
        st.error(CONSEJOS[nivel])
    elif nivel == "Medio":
        st.warning(CONSEJOS[nivel])
    else:
        st.success(CONSEJOS[nivel])


def pantalla_ingreso():
    """Crea la bóveda (la primera vez) o la abre con la clave maestra."""
    st.title("🔐 Gestor de Contraseñas Inteligente")

    if not boveda.existe_boveda():
        st.subheader("Crea tu bóveda")
        st.info("Elige una clave maestra. No se guarda en ningún lado: si la olvidas, no hay forma de recuperar la bóveda.")
        with st.form("crear"):
            clave = st.text_input("Clave maestra", type="password")
            confirmacion = st.text_input("Repite la clave maestra", type="password")
            enviado = st.form_submit_button("Crear bóveda")
        if enviado:
            if len(clave) < LONGITUD_MINIMA_MAESTRA:
                st.error(f"La clave maestra debe tener al menos {LONGITUD_MINIMA_MAESTRA} caracteres.")
            elif clave != confirmacion:
                st.error("Las dos claves no coinciden.")
            else:
                st.session_state["llave"] = boveda.crear_boveda(clave)
                st.rerun()
    else:
        st.subheader("Abre tu bóveda")
        with st.form("abrir"):
            clave = st.text_input("Clave maestra", type="password")
            enviado = st.form_submit_button("Abrir")
        if enviado:
            try:
                st.session_state["llave"] = boveda.abrir_boveda(clave)
                st.rerun()
            except ValueError as error:
                st.error(str(error))


def pestana_contrasenas(llave, credenciales):
    """Formulario para guardar credenciales y lista de las guardadas con su semáforo."""
    with st.form("nueva", clear_on_submit=True):
        st.subheader("Guardar una contraseña")
        sitio = st.text_input("Sitio o aplicación")
        usuario = st.text_input("Usuario o correo")
        contrasena = st.text_input("Contraseña", type="password")
        guardar = st.form_submit_button("Guardar")
    if guardar:
        if sitio and usuario and contrasena:
            boveda.agregar_credencial(llave, sitio, usuario, contrasena)
            st.rerun()
        else:
            st.warning("Llena los tres campos.")

    st.subheader("Mis contraseñas")
    if not credenciales:
        st.info("Todavía no hay contraseñas guardadas.")
    for cred in credenciales:
        resultado = analizar(cred["contrasena"])
        icono = SEMAFORO[resultado["nivel"]]
        with st.expander(f"{icono} {cred['sitio']} · {cred['usuario']} · riesgo {resultado['puntaje']}"):
            if st.checkbox("Mostrar contraseña", key=f"ver_{cred['id']}"):
                st.code(cred["contrasena"])
            else:
                st.code("•" * len(cred["contrasena"]))
            st.caption(f"Guardada: {cred['creada']}")
            mostrar_resultado(resultado)
            if st.button("Eliminar", key=f"borrar_{cred['id']}"):
                boveda.eliminar_credencial(cred["id"])
                st.rerun()


def pestana_analizar():
    """Analiza cualquier contraseña sin guardarla, y genera contraseñas seguras."""
    st.subheader("Analizar una contraseña")
    st.caption("No se guarda. A Pwned Passwords solo se envían los 5 primeros caracteres de su hash.")
    with st.form("analizar"):
        contrasena = st.text_input("Contraseña a analizar", type="password")
        enviado = st.form_submit_button("Analizar")
    if enviado and contrasena:
        mostrar_resultado(analizar(contrasena))

    st.divider()
    st.subheader("Generar una contraseña segura")
    tipo = st.radio("Tipo", ["Aleatoria (más segura)", "Frase (más fácil de recordar)"], horizontal=True)
    if st.button("Generar"):
        if tipo.startswith("Aleatoria"):
            st.session_state["generada"] = generar_aleatoria()
        else:
            st.session_state["generada"] = generar_frase()
    if "generada" in st.session_state:
        generada = st.session_state["generada"]
        st.code(generada)
        resultado = analizar(generada)
        st.write(f"Riesgo: {SEMAFORO[resultado['nivel']]} **{resultado['puntaje']} / 100** · "
                 f"tiempo para adivinarla: {traducir_tiempo(resultado['tiempo_para_adivinarla'])}")


def pestana_panel(credenciales):
    """Resumen del riesgo de toda la bóveda."""
    st.subheader("Panel de riesgo")
    if not credenciales:
        st.info("Guarda contraseñas para ver el panel.")
        return

    filas = []
    for cred in credenciales:
        resultado = analizar(cred["contrasena"])
        filas.append({
            "Sitio": cred["sitio"],
            "Usuario": cred["usuario"],
            "Riesgo": resultado["puntaje"],
            "Nivel": f"{SEMAFORO[resultado['nivel']]} {resultado['nivel']}",
            "Veces filtrada": resultado["veces_filtrada"],
            "contrasena": cred["contrasena"],
        })
    tabla = pd.DataFrame(filas)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Riesgo promedio", f"{tabla['Riesgo'].mean():.0f} / 100")
    col2.metric("🔴 Alto", int((tabla["Riesgo"] >= 60).sum()))
    col3.metric("🟡 Medio", int(tabla["Riesgo"].between(30, 59).sum()))
    col4.metric("🟢 Bajo", int((tabla["Riesgo"] < 30).sum()))

    repetidas = tabla.groupby("contrasena")["Sitio"].apply(list)
    repetidas = repetidas[repetidas.apply(len) > 1]
    if repetidas.empty:
        st.success("No repites contraseñas entre sitios. ✅")
    for sitios in repetidas:
        st.warning(f"⚠️ Usas la misma contraseña en: {', '.join(sitios)}. Si se filtra una, caen todas.")

    st.bar_chart(tabla.set_index("Sitio")["Riesgo"])
    st.dataframe(tabla.drop(columns="contrasena").sort_values("Riesgo", ascending=False), hide_index=True)


# ---------------------------------------------------------------------
# Programa principal
if "llave" not in st.session_state:
    pantalla_ingreso()
else:
    llave = st.session_state["llave"]
    with st.sidebar:
        st.write("🔓 Bóveda abierta")
        if st.button("🔄 Volver a analizar"):
            st.session_state["analisis"] = {}
            st.rerun()
        if st.button("Cerrar bóveda"):
            st.session_state.clear()
            st.rerun()
    st.title("🔐 Gestor de Contraseñas Inteligente")
    credenciales = boveda.listar_credenciales(llave)
    tab1, tab2, tab3 = st.tabs(["🔑 Mis contraseñas", "🔍 Analizar", "📊 Panel de riesgo"])
    with tab1:
        pestana_contrasenas(llave, credenciales)
    with tab2:
        pestana_analizar()
    with tab3:
        pestana_panel(credenciales)