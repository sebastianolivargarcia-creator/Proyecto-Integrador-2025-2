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

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    # GET: render landing/index page. POST: accept uploaded Excel and process it.
    if request.method == 'GET':
        return render_template('index.html', profesor=getattr(current_user, 'nombre', ''))

    try:
        archivo = request.files.get('archivo')
        if not archivo:
            flash("No se subió archivo.", "warning")
            return redirect(url_for('index'))

        uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
        os.makedirs(uploads_dir, exist_ok=True)
        ruta = os.path.join(uploads_dir, archivo.filename)
        archivo.save(ruta)

        try:
            df = pd.read_excel(ruta)
        except Exception as e:
            return jsonify({"ok": False, "message": f"Error leyendo Excel: {e}"}), 400

        # Reutilizar la normalización/mapeo similar a /procesar
        df.columns = [str(c).strip() for c in df.columns]
        candidatos = {
            'FALLAS1': ['FALLAS1', 'FALLAS 1', 'FALLAS_1', 'FALLAS-1', 'FALLA1', 'FALLA_1'],
            'FALLAS2': ['FALLAS2', 'FALLAS 2', 'FALLAS_2', 'FALLAS-2', 'FALLA2', 'FALLA_2'],
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
        esenciales = ['FALLAS1', 'FALLAS2', 'NOTA1', 'NOTA2', 'VEZVISTA', 'PROGRAMA_ACADEMICO']
        for e in esenciales:
            if e in df.columns and e not in mapping:
                mapping[e] = e
        faltantes = [e for e in esenciales if e not in mapping]
        if faltantes:
            return jsonify({"ok": False, "message": f"Faltan columnas requeridas: {', '.join(faltantes)}"}), 400

        rename_map = {v: k for k, v in mapping.items()}
        df = df.rename(columns=rename_map)

        for col in ['FALLAS1', 'FALLAS2', 'NOTA1', 'NOTA2']:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        df['FALLAS_TOTALES'] = df['FALLAS1'].fillna(0) + df['FALLAS2'].fillna(0)

        # Aplicar la regla simple y el modelo como en /procesar
        df['Deserta'] = 0
        df.loc[df['FALLAS_TOTALES'] >= 13, 'Deserta'] = 1
        df_sin_perder = df[df['Deserta'] == 0]
        if not df_sin_perder.empty:
            X = df_sin_perder[['NOTA1', 'NOTA2', 'FALLAS1', 'FALLAS2', 'VEZVISTA']]

            X_numeric = X.copy()
            for col in X.columns:
                coerced = pd.to_numeric(X_numeric[col], errors='coerce')
                if not coerced.dropna().empty:
                    X_numeric[col] = coerced.fillna(coerced.median())
                else:
                    X_numeric[col] = coerced.fillna(0)
            try:
                # Debugging: log shapes and sample data to help diagnose why predictions may be all zeros
                print('[predict] X_numeric.shape=', X_numeric.shape)
                try:
                    print('[predict] X_numeric.head=\n', X_numeric.head().to_dict())
                except Exception:
                    print('[predict] could not print head')
                try:
                    print('[predict] dtypes=\n', X_numeric.dtypes.to_dict())
                except Exception:
                    pass
                for col in X_numeric.columns:
                    try:
                        med = pd.to_numeric(X_numeric[col], errors='coerce').median()
                        print(f'[predict] median {col} =', med)
                    except Exception:
                        pass

                preds = modelo.predict(X_numeric)
                # If model supports predict_proba, show some probabilities for inspection
                try:
                    if hasattr(modelo, 'predict_proba'):
                        probs = modelo.predict_proba(X_numeric)[:, 1]
                        print('[predict] sample probs=', probs[:5].tolist())
                        print('[predict] mean proba=', float(probs.mean()))
                except Exception as e:
                    print('[predict] predict_proba error', e)

                # Log distribution of predictions
                import numpy as _np
                uniques, counts = _np.unique(preds, return_counts=True)
                print('[predict] preds uniques=', dict(zip(uniques.tolist(), counts.tolist())))

                df.loc[df['Deserta'] == 0, 'Prediccion_Modelo'] = preds
                # If all predictions are 0, inform via flash to help debugging
                if len(uniques) == 1 and uniques[0] == 0:
                    flash('Aviso: el modelo devolvió todas las predicciones como 0 (sin riesgo). Revisar entradas o reentrenar.', 'warning')
            except Exception as ex:
                print('[predict] modelo.predict error:', ex)
                import traceback as _tb
                _tb.print_exc()
                flash('Error al ejecutar el modelo: ' + str(ex), 'danger')
                # As fallback colocar Prediccion_Modelo igual a Deserta para no bloquear el flujo
                df.loc[df['Deserta'] == 0, 'Prediccion_Modelo'] = df.loc[df['Deserta'] == 0, 'Deserta']
        else:
            df['Prediccion_Modelo'] = df['Deserta']

        # Convertir la predicción a etiquetas legibles para la vista
        try:
            df['En_Riesgo'] = df['Prediccion_Modelo'].apply(lambda x: "Sí" if int(x) == 1 else "No")
        except Exception:
            # si por alguna razón Prediccion_Modelo tiene valores 0/1 o strings
            df['En_Riesgo'] = df['Prediccion_Modelo'].apply(lambda x: "Sí" if str(x) in ['1', 'True', 'true'] else "No")

        # Columnas para mostrar en la tabla de resultados
        columnas = [
            'PROGRAMA_ACADEMICO', 'APELLIDOS_Y_NOMBRES', 'NOM_MATERIA',
            'NOTA1', 'NOTA2', 'FALLAS1', 'FALLAS2', 'VEZVISTA', 'En_Riesgo'
        ]

        # Asegurarse de que las columnas existen (si faltan, rellenar con vacíos)
        for c in columnas:
            if c not in df.columns:
                df[c] = ''

        df_vista = df[columnas].to_dict(orient='records')

        # Guardar un Excel procesado en uploads/ para descarga y uso en dashboard
        uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
        os.makedirs(uploads_dir, exist_ok=True)
        salida = os.path.join(uploads_dir, "resultados_procesados.xlsx")
        try:
            df.to_excel(salida, index=False)
        except Exception as e:
            print('Error guardando resultados_excel:', e)

        return render_template(
            'resultados.html',
            datos=df_vista,
            profesor=current_user.nombre,
            excel_path='/' + salida.replace('\\', '/'),
            excel_name=os.path.basename(salida)
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "message": f"Error interno del servidor: {e}"}), 500


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

    # Si está cerca por faltas (p. ej. 8+ faltas) o ya por la regla 13
    if fallas_tot >= 8 and (prom is None or prom >= 3.0):
        base = random.choice(consejos_faltas)
        detalle = f" (Registro actual de faltas: {int(fallas_tot)})"
        return base + detalle

    # Si nota baja
    if prom is not None and prom < 3.0:
        base = random.choice(consejos_notas)
        detalle = f" (Promedio: {prom:.2f})"
        return base + detalle

    # Si ambas cosas
    if fallas_tot >= 8 and prom is not None and prom < 3.0:
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


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Renderiza la página del dashboard donde el profesor podrá subir un archivo
    y ver gráficas comparando estudiantes en riesgo vs no en riesgo."""
    return render_template('dashboard.html', profesor=current_user.nombre)
    # permitir que se pase un nombre de archivo ya procesado (basename only)
    file = request.args.get('file', '')
    return render_template('dashboard.html', profesor=current_user.nombre, initial_file=file)


@app.route('/dashboard/process', methods=['POST'])
@login_required
def dashboard_process():
    archivo = request.files.get('archivo')
    if not archivo:
        return jsonify({"ok": False, "message": "No se subió archivo."}), 400

    uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    ruta = os.path.join(uploads_dir, archivo.filename)
    archivo.save(ruta)

    try:
        df = pd.read_excel(ruta)
    except Exception as e:
        return jsonify({"ok": False, "message": f"Error leyendo Excel: {e}"}), 400

    # Reutilizar la normalización/mapeo similar a /procesar
    df.columns = [str(c).strip() for c in df.columns]
    candidatos = {
        'FALLAS1': ['FALLAS1', 'FALLAS 1', 'FALLAS_1', 'FALLAS-1', 'FALLA1', 'FALLA_1'],
        'FALLAS2': ['FALLAS2', 'FALLAS 2', 'FALLAS_2', 'FALLAS-2', 'FALLA2', 'FALLA_2'],
        'NOTA1': ['NOTA1', 'NOTA 1', 'NOTA_1', 'NOTAS1'],
        'NOTA2': ['NOTA2', 'NOTA 2', 'NOTA_2', 'NOTAS2'],
        'VEZVISTA': ['VEZVISTA', 'VEZ VISTA', 'VEZ_VISTA']
    }
    cols_lower = {c.lower(): c for c in df.columns}
    mapping = {}
    for esperado, variantes in candidatos.items():
        encontrado = None
        for v in variantes:
            if v.lower() in cols_lower:
                encontrado = cols_lower[v.lower()]
                break
        if encontrado:
            mapping[esperado] = encontrado
    esenciales = ['FALLAS1', 'FALLAS2', 'NOTA1', 'NOTA2', 'PROGRAMA_ACADEMICO']
    for e in esenciales:
        if e in df.columns and e not in mapping:
            mapping[e] = e
    faltantes = [e for e in esenciales if e not in mapping]
    if faltantes:
        return jsonify({"ok": False, "message": f"Faltan columnas requeridas: {', '.join(faltantes)}"}), 400

    rename_map = {v: k for k, v in mapping.items()}
    df = df.rename(columns=rename_map)

    for col in ['FALLAS1', 'FALLAS2', 'NOTA1', 'NOTA2']:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df['FALLAS_TOTALES'] = df['FALLAS1'].fillna(0) + df['FALLAS2'].fillna(0)

    # Aplicar la regla simple y el modelo como en /procesar
    df['Deserta'] = 0
    df.loc[df['FALLAS_TOTALES'] >= 13, 'Deserta'] = 1
    df_sin_perder = df[df['Deserta'] == 0]
    if not df_sin_perder.empty:
        X = df_sin_perder[['NOTA1', 'NOTA2', 'FALLAS1', 'FALLAS2', 'VEZVISTA']]
        X_numeric = X.copy()
        for col in X.columns:
            coerced = pd.to_numeric(X_numeric[col], errors='coerce')
            if not coerced.dropna().empty:
                X_numeric[col] = coerced.fillna(coerced.median())
            else:
                X_numeric[col] = coerced.fillna(0)
        try:
            preds = modelo.predict(X_numeric)
            df.loc[df['Deserta'] == 0, 'Prediccion_Modelo'] = preds
        except Exception:
            df.loc[df['Deserta'] == 0, 'Prediccion_Modelo'] = 0
    else:
        df['Prediccion_Modelo'] = df['Deserta']

    df['En_Riesgo'] = df['Prediccion_Modelo'].apply(lambda x: 1 if int(x) == 1 else 0)

    total = int(len(df))
    at_risk = int(df['En_Riesgo'].sum())
    safe = total - at_risk

    # Agrupar por programa
    by_program = {}
    if 'PROGRAMA_ACADEMICO' in df.columns:
        grouped = df.groupby('PROGRAMA_ACADEMICO')
        for prog, g in grouped:
            ar = int(g['En_Riesgo'].sum())
            sz = int(len(g))
            by_program[str(prog)] = {"at_risk": ar, "safe": sz - ar, "total": sz}

    return jsonify({"ok": True, "total": total, "at_risk": at_risk, "safe": safe, "by_program": by_program})


@app.route('/dashboard/load', methods=['GET'])
@login_required
def dashboard_load():
    """Carga un archivo ya existente desde uploads/ por su nombre (basename) y devuelve el mismo JSON que /dashboard/process."""
    filename = request.args.get('file', '')
    if not filename:
        return jsonify({"ok": False, "message": "No se indicó archivo."}), 400
    # validar basename para evitar traversal
    safe_name = os.path.basename(filename)
    uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
    ruta = os.path.join(uploads_dir, safe_name)
    if not os.path.exists(ruta):
        return jsonify({"ok": False, "message": "Archivo no encontrado en uploads."}), 404

    try:
        df = pd.read_excel(ruta)
    except Exception as e:
        return jsonify({"ok": False, "message": f"Error leyendo Excel: {e}"}), 400

    # el resto del procesamiento es idéntico al de /dashboard/process; para evitar duplicación se repite aquí
    df.columns = [str(c).strip() for c in df.columns]
    candidatos = {
        'FALLAS1': ['FALLAS1', 'FALLAS 1', 'FALLAS_1', 'FALLAS-1', 'FALLA1', 'FALLA_1'],
        'FALLAS2': ['FALLAS2', 'FALLAS 2', 'FALLAS_2', 'FALLAS-2', 'FALLA2', 'FALLA_2'],
        'NOTA1': ['NOTA1', 'NOTA 1', 'NOTA_1', 'NOTAS1'],
        'NOTA2': ['NOTA2', 'NOTA 2', 'NOTA_2', 'NOTAS2'],
        'VEZVISTA': ['VEZVISTA', 'VEZ VISTA', 'VEZ_VISTA']
    }
    cols_lower = {c.lower(): c for c in df.columns}
    mapping = {}
    for esperado, variantes in candidatos.items():
        encontrado = None
        for v in variantes:
            if v.lower() in cols_lower:
                encontrado = cols_lower[v.lower()]
                break
        if encontrado:
            mapping[esperado] = encontrado
    esenciales = ['FALLAS1', 'FALLAS2', 'NOTA1', 'NOTA2', 'PROGRAMA_ACADEMICO']
    for e in esenciales:
        if e in df.columns and e not in mapping:
            mapping[e] = e
    faltantes = [e for e in esenciales if e not in mapping]
    if faltantes:
        return jsonify({"ok": False, "message": f"Faltan columnas requeridas: {', '.join(faltantes)}"}), 400

    rename_map = {v: k for k, v in mapping.items()}
    df = df.rename(columns=rename_map)
    for col in ['FALLAS1', 'FALLAS2', 'NOTA1', 'NOTA2']:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df['FALLAS_TOTALES'] = df['FALLAS1'].fillna(0) + df['FALLAS2'].fillna(0)
    df['Deserta'] = 0
    df.loc[df['FALLAS_TOTALES'] >= 13, 'Deserta'] = 1
    df_sin_perder = df[df['Deserta'] == 0]
    if not df_sin_perder.empty:
        X = df_sin_perder[['NOTA1', 'NOTA2', 'FALLAS1', 'FALLAS2', 'VEZVISTA']]
        X_numeric = X.copy()
        for col in X.columns:
            coerced = pd.to_numeric(X_numeric[col], errors='coerce')
            if not coerced.dropna().empty:
                X_numeric[col] = coerced.fillna(coerced.median())
            else:
                X_numeric[col] = coerced.fillna(0)
        try:
            preds = modelo.predict(X_numeric)
            df.loc[df['Deserta'] == 0, 'Prediccion_Modelo'] = preds
        except Exception:
            df.loc[df['Deserta'] == 0, 'Prediccion_Modelo'] = 0
    else:
        df['Prediccion_Modelo'] = df['Deserta']
    df['En_Riesgo'] = df['Prediccion_Modelo'].apply(lambda x: 1 if int(x) == 1 else 0)
    total = int(len(df))
    at_risk = int(df['En_Riesgo'].sum())
    safe = total - at_risk
    by_program = {}
    if 'PROGRAMA_ACADEMICO' in df.columns:
        grouped = df.groupby('PROGRAMA_ACADEMICO')
        for prog, g in grouped:
            ar = int(g['En_Riesgo'].sum())
            sz = int(len(g))
            by_program[str(prog)] = {"at_risk": ar, "safe": sz - ar, "total": sz}
    return jsonify({"ok": True, "total": total, "at_risk": at_risk, "safe": safe, "by_program": by_program})




if __name__ == '__main__':
    app.run(debug=True)
