# Gestor de Contraseñas Inteligente con Análisis Predictivo de Vulnerabilidades

Prueba de concepto de un gestor de contraseñas que, además de guardar las credenciales **cifradas**, estima su **riesgo de 0 a 100** con datos reales de filtraciones y lo muestra con un semáforo 🟢🟡🔴.

**Proyecto de curso** · Electiva Técnica I: Ciencia de Datos · Escuela Tecnológica Instituto Técnico Central (ETITC) · 2026-2
**Autores:** Juanitha González Moreno · Daniel Felipe Toro Suárez
**Profesor:** Elías Buitrago Bolívar

---

## ¿Qué hace?

- **Guarda credenciales cifradas** (sitio, usuario y contraseña) con una clave maestra que nunca se almacena.
- **Calcula el riesgo** de cada contraseña combinando cuatro fuentes:

  | Fuente | Peso | Qué aporta |
  |---|---|---|
  | [Pwned Passwords](https://haveibeenpwned.com/Passwords) | 35 % | Cuántas veces apareció en filtraciones reales (consulta con k-anonimato) |
  | [zxcvbn](https://github.com/dropbox/zxcvbn) | 30 % | Qué tan fácil es de adivinar |
  | Modelo propio (Random Forest) | 25 % | Probabilidad de ser de las que se filtran |
  | RockYou | 10 % | Si está entre el millón de contraseñas más usadas |

  Sobre ese promedio se aplican reglas mínimas: contraseñas filtradas, adivinables en segundos o formadas por una palabra común con números siempre salen en riesgo alto.
- **Explica el porqué**: razones y un consejo para cada contraseña.
- **Genera contraseñas seguras** (aleatorias o frases fáciles de recordar).
- **Panel de riesgo** con el promedio de la bóveda y aviso de contraseñas repetidas entre sitios.

## Resultados principales

| | Resultado |
|---|---|
| El problema | 1.046 brechas reales (2007–2026) con 17.767 millones de cuentas afectadas; el 64,3 % expuso contraseñas |
| Datos limpios | 14.343.462 contraseñas de RockYou · 669.605 de Kaggle |
| Modelo 1 (fortaleza, Kaggle) | 100 % de exactitud → reveló que las etiquetas dependen **solo de la longitud** |
| Modelo 2 (¿aparece en otra filtración?) | AUC 0,846 · recall 83,8 % · exactitud 72,5 % |
| Privacidad | La contraseña nunca sale completa del equipo; la bóveda solo guarda texto cifrado |

El análisis completo está en el informe final.

---

## Estructura del repositorio

```
gestor-contrasenas-inteligente/
├── app.py                      ← la aplicación (Streamlit)
├── requirements.txt            ← librerías con sus versiones exactas
├── src/                        ← código reutilizable (lo usan los notebooks y la app)
│   ├── caracteristicas.py      ← convierte una contraseña en 16 variables numéricas
│   ├── filtraciones.py         ← consulta Pwned Passwords con k-anonimato
│   ├── riesgo.py               ← motor de riesgo: puntaje de 0 a 100, nivel y razones
│   ├── boveda.py               ← bóveda cifrada (PBKDF2 + Fernet + SQLite)
│   └── generador.py            ← generador de contraseñas seguras
├── notebooks/
│   ├── 01_exploracion_inicial.ipynb
│   ├── 02_limpieza.ipynb               ← limpia los datos y los guarda en Parquet
│   ├── 03_analisis_exploratorio.ipynb  ← las 10 gráficas del análisis
│   ├── 04_modelo.ipynb                 ← características y modelo 1 (fortaleza)
│   ├── 05_modelo_vulnerabilidad.ipynb  ← modelo 2 (el que usa la app)
│   ├── 06_motor_riesgo.ipynb           ← pruebas de Pwned Passwords y del motor
│   └── 07_boveda.ipynb                 ← pruebas de la bóveda cifrada
├── docs/figuras/               ← gráficas generadas por los notebooks
├── data/                       ← NO se sube a GitHub (ver "Datos")
│   ├── raw/                    ← datos originales
│   └── processed/              ← datos limpios en Parquet
└── models/                     ← NO se sube a GitHub (se crea con los notebooks)
```

---

## Cómo reproducir el proyecto

### Requisitos

- Windows 10/11 (también funciona en Linux o macOS cambiando los comandos de PowerShell)
- [Python 3.14](https://www.python.org/downloads/) y [Git](https://git-scm.com/)
- Conexión a internet (para Pwned Passwords; sin conexión la app sigue funcionando y lo indica)

### 1. Descargar el código e instalar las librerías

```powershell
git clone https://github.com/danieltoro-source/gestor-contrasenas-inteligente.git
cd gestor-contrasenas-inteligente
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Si PowerShell dice *"running scripts is disabled"*, ejecuta una vez:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### 2. Descargar los datos

Los datos **no están en el repositorio**: son pesados y son contraseñas filtradas, que no deben publicarse. Descárgalos en `data/raw/` con estos nombres:

| Archivo | De dónde | Nombre en `data/raw/` |
|---|---|---|
| RockYou | [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases) (`rockyou.txt.tar.gz`, descomprimir) | `rockyou.txt` |
| Password Strength Dataset | [Kaggle](https://www.kaggle.com/datasets/bhavikbb/password-strength-classifier-dataset) (pide iniciar sesión; el archivo se llama `data.csv`) | `kaggle_password_strength.csv` |
| Catálogo de brechas | [API de Have I Been Pwned](https://haveibeenpwned.com/api/v3/breaches) (guardar la respuesta JSON) | `hibp_breaches.json` |

### 3. Ejecutar los notebooks en orden

Abre la carpeta en VS Code, elige el kernel `.venv` y ejecuta cada notebook completo (**Run All**) **en este orden**, porque cada uno usa lo que crea el anterior:

1. `02_limpieza` → crea `data/processed/rockyou_limpio.parquet` y `kaggle_limpio.parquet`
2. `03_analisis_exploratorio` → crea las gráficas en `docs/figuras/`
3. `04_modelo` → crea `kaggle_caracteristicas.parquet` y `models/modelo_fortaleza.joblib`
4. `05_modelo_vulnerabilidad` → crea `models/modelo_vulnerabilidad.joblib`

Los notebooks 06 y 07 son pruebas y no son necesarios para la app.

### 4. Abrir la aplicación

```powershell
streamlit run app.py
```

Se abre en el navegador en `http://localhost:8501` (solo en tu equipo). La primera vez pide **crear la bóveda** con una clave maestra de al menos 12 caracteres. La primera carga tarda unos segundos mientras lee el modelo y RockYou.

---

## Seguridad y uso responsable

- **Clave maestra:** nunca se guarda. Se convierte en la llave con PBKDF2-HMAC-SHA256, una sal aleatoria y 600.000 iteraciones.
- **Bóveda:** `data/boveda.db` (SQLite) solo contiene texto cifrado con Fernet (AES + HMAC). Si se olvida la clave maestra, **no hay forma de recuperarla**: es intencional.
- **Pwned Passwords:** solo se envían los 5 primeros caracteres del hash SHA-1 de la contraseña (k-anonimato).
- **Datos:** los datasets se usan **solo** para estadística y entrenamiento de modelos. Al probar la app usa contraseñas inventadas, nunca las reales.

## Limitaciones conocidas

- No verifica correos en filtraciones (esa búsqueda de Have I Been Pwned es de pago).
- No conoce los datos personales del usuario: una contraseña con su nombre y su documento queda en riesgo medio.
- zxcvbn usa diccionarios en inglés.
- Es una aplicación local de un solo usuario, sin sincronización entre dispositivos.

## Tecnologías

Python · pandas · pyarrow · matplotlib · scikit-learn · joblib · zxcvbn · requests · cryptography · Streamlit · SQLite
