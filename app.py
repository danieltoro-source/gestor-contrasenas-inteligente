"app de gestión de contraseñas (Streamlit)"

import streamlit as st
from src import boveda

st.set_page_config(page_title="Gestor de Contraseñas", page_icon="🔐", layout="centered")

LONGITUD_MINIMA_MAESTRA = 12

def pantalla_ingreso():
    "crar la boveda o abrirla con llave maestra"
    st.title("🔐 Gestor de Contraseñas Inteligente")

    if not boveda.existe_boveda():
        st.subheader("Crear bóveda")
        st.info("Elige una clave maestra. No se guarda en ningún lado: si la olvidas, no hay forma de recuperar la bóveda.")
        with st.form("crear"):
            clave = st.text_input("Clave maestra", type="password")
            confirmacion = st.text_input("Repite la clave", type="password")
            enviado = st.form_submit_button("Crear boveda")

        if enviado:
            if len(clave) < LONGITUD_MINIMA_MAESTRA:
                st.error(f"La clave maestra debe tener al menos {LONGITUD_MINIMA_MAESTRA} caracteres")
            elif clave != confirmacion:
                st.error("Las dos clavees no coinciden")
            else:
                st.session_state["llave"] = boveda.crear_boveda(clave)
                st.rerun()
    else:
        st.subheader("Abre tu boveda")
        with st.form("abrir"):
            clave = st.text_input("Clave maestra", type="password")
            enviado = st.form_submit_button("Abrir")

        if enviado:
            try:
                st.session_state["llave"] = boveda.abrir_boveda(clave)
                st.rerun()
            except ValueError as error:
                st.error(str(error))

def pestana_contrasenas(llave):
    "Formulario para guardar credenciales y lista de las guardadas"
    with st.form("nueva", clear_on_submit=True):
        st.subheader("Guardar una contraseña")
        sitio = st.text_input("Sitio o aplicación")
        usuario = st.text_input("Usuario o correo")
        contrasena = st.text_input("Contraseña", type="password")
        guardar = st.form_submit_button("Guardar")
    if guardar:
        if sitio and usuario and contrasena:
            boveda.agregar_credencial(llave, sitio, usuario, contrasena)
            st.success(f"Se guardó la contraseña de {sitio}.")
        else:
            st.warning("Llena los tres campos")

    st.subheader("Mis contraseñas")
    credenciales = boveda.listar_credenciales(llave)
    if not credenciales:
        st.info("Todavía no hay contraseñas guardadas.")
    for cred in credenciales:
        with st.expander(f"{cred['sitio']} · {cred['usuario']}"):
            if st.checkbox("Mostrar contraseña", key=f"ver_{cred['id']}"):
                st.code(cred["contrasena"])
            else:
                st.code("•" * len(cred["contrasena"]))
            st.caption(f"Guardada: {cred['creada']}")
            if st.button("Eliminar", key=f"borrar_{cred['id']}"):
                boveda.eliminar_credencial(cred["id"])
                st.rerun()



# Programa principal
if "llave" not in st.session_state:
    pantalla_ingreso()
else:
    llave = st.session_state["llave"]
    with st.sidebar:
        st.write("🔓 Bóveda abierta")
        if st.button("Cerrar bóveda"):
            del st.session_state["llave"]
            st.rerun()
    st.title("🔐 Gestor de Contraseñas Inteligente")
    pestana_contrasenas(llave)

