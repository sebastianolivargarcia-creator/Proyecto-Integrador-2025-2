from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
import datetime
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
    UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import joblib
import os
import firebase_admin
from firebase_admin import credentials, auth, firestore

# ---------------- CONFIGURACIÓN INICIAL ----------------
app = Flask(__name__)
app.secret_key = "SILENE_TE_AMO_CON_TODO_MI_CORAZON"

# ---------------- INICIALIZAR FIREBASE ----------------
cred_path = os.path.join(os.path.dirname(__file__), "eduquantum-16b89-firebase-adminsdk-fbsvc-7775b942f7.json")

if not os.path.exists(cred_path):
    raise FileNotFoundError(f"No se encontró el archivo de credenciales: {cred_path}")

cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)
db = firestore.client()

# ---------------- FLASK-LOGIN SETUP ----------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, nombre):
        self.id = id
        self.nombre = nombre

@login_manager.user_loader
def load_user(user_id):
    doc = db.collection("usuarios").document(user_id).get()
    if doc.exists:
        data = doc.to_dict()
        return User(id=data["email"], nombre=data["nombre"])
    return None

# ---------------- CARGAR MODELO ----------------
modelo_path = os.path.join(os.path.dirname(__file__), "modelo_desercion.pkl")

if not os.path.exists(modelo_path):
    raise FileNotFoundError(f"No se encontró el modelo: {modelo_path}")

modelo = joblib.load(modelo_path)

# ---------------- RUTAS ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user_ref = db.collection("usuarios").document(email)
        user_doc = user_ref.get()

        if user_doc.exists:
            user_data = user_doc.to_dict()
            if check_password_hash(user_data["password_hash"], password):
                user_obj = User(id=user_data["email"], nombre=user_data["nombre"])
                login_user(user_obj)
                flash("Inicio de sesión correcto ✅", "success")
                return redirect(url_for("index"))
            else:
                flash("Contraseña incorrecta ❌", "danger")
        else:
            flash("El usuario no existe ❌", "danger")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form.get("nombre", "")
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not nombre or not email or not password:
            flash("Por favor, completa todos los campos.", "warning")
            return redirect(url_for("register"))

        user_ref = db.collection("usuarios").document(email)
        if user_ref.get().exists:
            flash("Este correo ya está registrado.", "danger")
            return redirect(url_for("register"))

        try:
            auth.create_user(email=email, password=password, display_name=nombre)
        except Exception as e:
            print("Error al registrar en Firebase Auth:", e)

        user_ref.set({
            "nombre": nombre,
            "email": email,
            "password_hash": generate_password_hash(password)
        })

        flash("Usuario registrado exitosamente. Inicia sesión.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión.", "info")
    return redirect(url_for("login"))

@app.route('/')
@login_required
def index():
    return render_template('index.html', profesor=current_user.nombre)

@app.route('/procesar', methods=['POST'])
@login_required
def procesar():
    archivo = request.files.get('archivo')
    if not archivo:
        flash("No se subió ningún archivo.", "danger")
        return redirect(url_for("index"))

    uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    ruta = os.path.join(uploads_dir, archivo.filename)
    archivo.save(ruta)

    df = pd.read_excel(ruta)

    # Normalizar nombres de columnas: quitar espacios extremos y pasar a mayúsculas
    df.columns = [str(c).strip() for c in df.columns]

    # Mapeo de columnas esperadas a posibles variantes en los archivos subidos
    candidatos = {
        'FALLAS1': ['FALLAS1', 'FALLAS 1', 'FALLAS_1', 'FALLAS-1', 'FALLA1', 'FALLA_1', 'FALLAS1.0'],
        'FALLAS2': ['FALLAS2', 'FALLAS 2', 'FALLAS_2', 'FALLAS-2', 'FALLA2', 'FALLA_2', 'FALLAS2.0'],
        'NOTA1': ['NOTA1', 'NOTA 1', 'NOTA_1', 'NOTAS1', 'NOTA1.0'],
        'NOTA2': ['NOTA2', 'NOTA 2', 'NOTA_2', 'NOTAS2', 'NOTA2.0'],
        'VEZVISTA': ['VEZVISTA', 'VEZ VISTA', 'VEZ_VISTA', 'VEZ-VISTA', 'VEZVISTAS'],
    }

    # Crear un diccionario inverso para buscar columnas existentes (case-insensitive)
    cols_lower = {c.lower(): c for c in df.columns}

    mapping = {}
    for esperado, variantes in candidatos.items():
        encontrado = None
        for v in variantes:
            if v.lower() in cols_lower:
                encontrado = cols_lower[v.lower()]
                break
        # Si no se encontró por variante, intentar por sufijo parcial (ej. columna que contiene 'FALLAS' y '1')
        if not encontrado:
            for col in df.columns:
                col_l = col.lower()
                if esperado.lower()[:5] in col_l and any(ch in col_l for ch in ['1', '2']):
                    # heurística: asignar si contiene el número
                    if esperado.endswith('1') and '1' in col_l:
                        encontrado = col
                        break
                    if esperado.endswith('2') and '2' in col_l:
                        encontrado = col
                        break
        if encontrado:
            mapping[esperado] = encontrado

    # Verificar que tenemos las columnas esenciales
    esenciales = ['FALLAS1', 'FALLAS2', 'NOTA1', 'NOTA2', 'VEZVISTA', 'PROGRAMA_ACADEMICO', 'APELLIDOS_Y_NOMBRES', 'NOM_MATERIA']
    faltantes = [e for e in esenciales if e not in mapping and e not in df.columns]
    # permitir que si la columna existe exactamente en df.columns, la usemos
    for e in esenciales:
        if e in df.columns and e not in mapping:
            mapping[e] = e

    if faltantes:
        flash(f"El archivo subido no contiene las columnas requeridas: {', '.join(faltantes)}. Revisa el formato del Excel.", 'danger')
        return redirect(url_for('index'))

    # Renombrar columnas según el mapping para el resto del flujo
    rename_map = {v: k for k, v in mapping.items()}
    df = df.rename(columns=rename_map)

    # Reglas de negocio
    # Asegurarse de que las columnas numéricas sean numéricas
    for col in ['FALLAS1', 'FALLAS2', 'NOTA1', 'NOTA2']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df['FALLAS_TOTALES'] = df['FALLAS1'].fillna(0) + df['FALLAS2'].fillna(0)
    df['Deserta'] = 0
    # Regla: marcar como deserta si suma de faltas cercana o superior a 13 (ajustada a 10)
    # o si el promedio de notas es menor a 3.2 (nuevo umbral)
    df.loc[(df['FALLAS_TOTALES'] >= 10) | ((df[['NOTA1','NOTA2']].mean(axis=1) < 3.2)), 'Deserta'] = 1

    # Inicializar Prediccion_Modelo con la regla simple (Deserta) para asegurar que
    # los casos ya marcados por la regla se conserven y no queden como NaN.
    df['Prediccion_Modelo'] = df['Deserta'].fillna(0).astype(int)

    df_sin_perder = df[df['Deserta'] == 0]
    if not df_sin_perder.empty:
        X = df_sin_perder[['NOTA1', 'NOTA2', 'FALLAS1', 'FALLAS2', 'VEZVISTA']]

        # Validar y convertir columnas a numéricas antes de predecir.
        # Coercionar valores no numéricos a NaN, registrar ejemplos y rellenar con la mediana.
        X_numeric = X.copy()
        problemas = {}
        for col in X.columns:
            coerced = pd.to_numeric(X_numeric[col], errors='coerce')
            # valores originales que no pudieron convertirse
            mask_bad = coerced.isna() & X_numeric[col].notna()
            if mask_bad.any():
                ejemplos = X_numeric.loc[mask_bad, col].unique().tolist()[:10]
                problemas[col] = ejemplos
            # rellenar NaN con la mediana de la columna (si existe) o con 0
            if not coerced.dropna().empty:
                X_numeric[col] = coerced.fillna(coerced.median())
            else:
                X_numeric[col] = coerced.fillna(0)

        if problemas:
            # Crear mensaje de advertencia corto y mostrar al usuario
            mensajes = []
            for c, ejemplos in problemas.items():
                ejemplos_txt = ", ".join(map(str, ejemplos))
                mensajes.append(f"{c}: {ejemplos_txt}")
            flash("Se encontraron valores no numéricos en las columnas: " + "; ".join(mensajes), "warning")

        try:
            preds = modelo.predict(X_numeric)
            # Asegurar longitud consistente
            if len(preds) == len(X_numeric):
                df.loc[df['Deserta'] == 0, 'Prediccion_Modelo'] = preds.astype(int)
            else:
                print('[procesar] Warning: longitud de preds != filas a predecir', len(preds), len(X_numeric))
        except Exception as ex:
            print('[procesar] modelo.predict error:', ex)
            # En caso de fallo del modelo, mantenemos la predicción basada en la regla
            # y no sobrescribimos Prediccion_Modelo
            pass
    else:
        df['Prediccion_Modelo'] = df['Deserta']

    # Normalizar Prediccion_Modelo y crear etiqueta legible
    df['Prediccion_Modelo'] = pd.to_numeric(df['Prediccion_Modelo'], errors='coerce').fillna(0).astype(int)
    df['En_Riesgo'] = df['Prediccion_Modelo'].apply(lambda x: "Sí" if int(x) == 1 else "No")

    # Debug / diagnóstico: imprimir conteos sencillos para verificar comportamiento
    try:
        total = len(df)
        by_rule = int((df['Deserta'] == 1).sum())
        by_model = int((df['Prediccion_Modelo'] == 1).sum())
        print(f"[procesar] total={total} marcados_por_regla={by_rule} marcados_por_modelo={by_model}")
    except Exception:
        pass

    columnas = [
        'PROGRAMA_ACADEMICO', 'APELLIDOS_Y_NOMBRES', 'NOM_MATERIA',
        'NOTA1', 'NOTA2', 'FALLAS1', 'FALLAS2', 'VEZVISTA', 'En_Riesgo'
    ]
    df_vista = df[columnas].to_dict(orient='records')

    salida = os.path.join(uploads_dir, "resultados_procesados.xlsx")
    df.to_excel(salida, index=False)

    return render_template(
        'resultados.html',
        datos=df_vista,
        profesor=current_user.nombre,
        excel_path=salida
    )


def generar_sugerencia_por_fila(fila):
    """Genera una sugerencia de texto variable basada en si el riesgo parece venir por faltas o por notas."""
    # Extraer valores seguros
    try:
        nota1 = float(fila.get('NOTA1') or 0)
    except Exception:
        nota1 = None
    try:
        nota2 = float(fila.get('NOTA2') or 0)
    except Exception:
        nota2 = None
    try:
        fallas1 = float(fila.get('FALLAS1') or 0)
    except Exception:
        fallas1 = 0
    try:
        fallas2 = float(fila.get('FALLAS2') or 0)
    except Exception:
        fallas2 = 0

    fallas_tot = (fallas1 or 0) + (fallas2 or 0)
    prom = None
    if nota1 is not None and nota2 is not None:
        prom = (nota1 + nota2) / 2.0

    consejos_faltas = [
        "Acércate y pregunta si hay dificultades personales o de transporte que expliquen las inasistencias.",
        "Solicita una breve reunión para entender las razones de las faltas y ofrecer apoyo o alternativas.",
        "Recomienda recursos institucionales (tutorías, consejería) y propone un plan de recuperación de asistencias.",
        "Pregunta si existen conflictos de horario o salud; plantea opciones para recuperar actividades perdidas."
    ]

    consejos_notas = [
        "Habla con el estudiante sobre su progreso y ofrece apoyo con ejercicios o tutorías.",
        "Revisa si el estudiante entiende los criterios de evaluación y sugiere recursos de refuerzo.",
        "Propón pequeñas metas de mejora y ofrece seguimiento semanal para que recupere confianza.",
        "Consulta sobre carga horaria o dificultades externas que afecten el estudio y sugiere ajustes."
    ]

    import random
    random.seed()  # usa semilla variable

    # Si está cerca por faltas (p. ej. 8+ faltas) o ya por la regla (>=10)
    if fallas_tot >= 8 and (prom is None or prom >= 3.2):
        base = random.choice(consejos_faltas)
        detalle = f" (Registro actual de faltas: {int(fallas_tot)})"
        return base + detalle

    # Si nota baja
    if prom is not None and prom < 3.2:
        base = random.choice(consejos_notas)
        detalle = f" (Promedio: {prom:.2f})"
        return base + detalle

    # Si ambas cosas
    if fallas_tot >= 8 and prom is not None and prom < 3.2:
        base = random.choice(consejos_faltas + consejos_notas)
        detalle = f" (Promedio: {prom:.2f}, Faltas: {int(fallas_tot)})"
        return base + detalle

    # Sugerencia por defecto
    return random.choice(consejos_notas + consejos_faltas)


@app.route('/sugerencia', methods=['POST'])
@login_required
def sugerencia():
    data = request.get_json() or {}
    # Esperamos los campos: APELLIDOS_Y_NOMBRES, NOTA1, NOTA2, FALLAS1, FALLAS2
    texto = generar_sugerencia_por_fila(data)
    return {"sugerencia": texto}


@app.route('/guardar_riesgo', methods=['POST'])
def guardar_riesgo():
    # Recibe un JSON con una lista de filas seleccionadas
    if not getattr(current_user, 'is_authenticated', False):
        return jsonify({"ok": False, "message": "no_auth"}), 401
    payload = request.get_json() or {}
    print(f"[guardar_riesgo] request from user={getattr(current_user, 'id', None)} payload_count={len(payload.get('seleccion', []))}")
    seleccion = payload.get('seleccion', [])
    if not isinstance(seleccion, list) or len(seleccion) == 0:
        return {"ok": False, "message": "No hay estudiantes seleccionados."}, 400

    # Guardar en la subcolección del usuario para mantener datos separados por profesor
    colec = db.collection('usuarios').document(current_user.id).collection('estudiantes_en_riesgo')
    guardados = 0
    for fila in seleccion:
        # Estandarizar documento
        doc = {
            'programa': fila.get('PROGRAMA_ACADEMICO'),
            'nombre': fila.get('APELLIDOS_Y_NOMBRES'),
            'materia': fila.get('NOM_MATERIA'),
            'nota1': fila.get('NOTA1'),
            'nota2': fila.get('NOTA2'),
            'fallas1': fila.get('FALLAS1'),
            'fallas2': fila.get('FALLAS2'),
            'vez_vista': fila.get('VEZVISTA'),
            'en_riesgo': fila.get('En_Riesgo'),
            'profesor_guardado': current_user.nombre,
            'fecha_guardado': firestore.SERVER_TIMESTAMP
        }
        try:
            colec.add(doc)
            guardados += 1
        except Exception as e:
            print("Error guardando en Firestore:", e)

    return jsonify({"ok": True, "guardados": guardados})


@app.route('/mis_guardados', methods=['GET'])
def mis_guardados():
    """Devuelve la lista de estudiantes guardados por el profesor autenticado."""
    if not getattr(current_user, 'is_authenticated', False):
        return jsonify({}), 401
    print(f"[mis_guardados] request from user={getattr(current_user, 'id', None)}")
    docs = db.collection('usuarios').document(current_user.id).collection('estudiantes_en_riesgo').stream()
    resultados = []
    for d in docs:
        data = d.to_dict()
        # Convertir campos no serializables (p.ej. datetime) a formatos simples
        if 'fecha_guardado' in data:
            ts = data['fecha_guardado']
            try:
                # si es datetime
                if isinstance(ts, datetime.datetime):
                    data['fecha_guardado'] = {'_seconds': int(ts.timestamp()), 'iso': ts.isoformat()}
                else:
                    # dejar tal cual si no es datetime
                    data['fecha_guardado'] = str(ts)
            except Exception:
                data['fecha_guardado'] = str(ts)
        data['id'] = d.id
        resultados.append(data)
    print(f"[mis_guardados] returning {len(resultados)} records")
    return jsonify(resultados)


@app.route('/test_json', methods=['GET'])
def test_json():
    return jsonify({"ok": True, "server_time": datetime.datetime.utcnow().isoformat()})


@app.route('/img/<path:filename>')
def img_file(filename):
    """Serve files from the project's img/ folder (used by templates).
    This avoids having to copy images into the static/ folder during development.
    """
    img_dir = os.path.join(os.path.dirname(__file__), 'img')
    return send_from_directory(img_dir, filename)


@app.route('/log_client_error', methods=['POST'])
def log_client_error():
    payload = request.get_json() or {}
    print("[client_error]", payload.get('message'))
    # opcionalmente imprimir stack
    if payload.get('stack'):
        print(payload.get('stack'))
    return jsonify({"ok": True})


@app.route('/reportar', methods=['GET'])
@login_required
def reportar():
    """Renderiza un formulario para reportar una sugerencia por correo.
    El formulario se abre como mailto: en el cliente (Outlook u otro cliente por defecto).
    """
    texto = request.args.get('texto', '')
    # correo del usuario autenticado (se guarda en current_user.id)
    user_email = getattr(current_user, 'id', '')
    profesor = getattr(current_user, 'nombre', '')
    # destinatario por defecto (puede ajustarse)
    destinatario_default = 'Asesor-Psicologo@ustabuca.edu.co'
    return render_template('reportar.html', texto=texto, user_email=user_email, profesor=profesor, destinatario=destinatario_default)




if __name__ == '__main__':
    app.run(debug=True)
