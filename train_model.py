"""
train_model.py
Script para re-entrenar el modelo de deserción según la regla indicada por el usuario:
- Target `DESERTO` = 1 si FALLAS_TOTALES >= 13 OR (PROMEDIO_NOTAS < 3.0)
- Usa columnas: NOTA1, NOTA2, FALLAS1, FALLAS2, VEZVISTA
- Guarda el pipeline completo en `modelo_desercion.pkl` (mismo nombre que usa la app)

Uso:
    python train_model.py --input Notas_1corte.xlsx

Ajustes/Asunciones:
- PROMEDIO_NOTAS = mean(NOTA1, NOTA2)
- NOTA se recorta a rango [1.0, 5.0] si hay valores fuera de rango
- Se coercean valores no numéricos y se imputan con la mediana
- Se usa RandomForest con class_weight='balanced'
"""

import argparse
import datetime
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier


def build_and_train(input_path, output_model_path="modelo_desercion.pkl", random_state=42):
    print("Leyendo dataset:", input_path)
    df = pd.read_excel(input_path)

    # Columnas esperadas
    expected_cols = ["NOTA1", "NOTA2", "FALLAS1", "FALLAS2", "VEZVISTA"]

    # Coercionar a numérico las columnas que usaremos
    for c in expected_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
        else:
            # Si falta alguna columna, crearla con NaN para evitar errores
            df[c] = np.nan

    # Normalizar notas al rango [1.0, 5.0] si aparecen valores fuera de rango
    for c in ["NOTA1", "NOTA2"]:
        df.loc[df[c].notna(), c] = df.loc[df[c].notna(), c].clip(lower=1.0, upper=5.0)

    # Construir variable FALLAS_TOTALES y PROMEDIO_NOTAS
    df["FALLAS_TOTALES"] = df["FALLAS1"].fillna(0) + df["FALLAS2"].fillna(0)
    df["PROMEDIO_NOTAS"] = df[["NOTA1", "NOTA2"]].mean(axis=1)

    # Crear target DESERTO segun la regla solicitada
    # DESERTO = 1 si FALLAS_TOTALES >= 13 OR PROMEDIO_NOTAS < 3.0
    df["DESERTO"] = ((df["FALLAS_TOTALES"] >= 13) | (df["PROMEDIO_NOTAS"] < 3.0)).astype(int)

    # Mantener nomenclatura similar al script original
    X = df[["NOTA1", "NOTA2", "FALLAS1", "FALLAS2", "VEZVISTA"]].copy()
    y = df["DESERTO"].copy()

    # Eliminar filas sin target o sin features utiles
    mask_valid = ~y.isna() & ~X.isna().all(axis=1)
    X = X[mask_valid]
    y = y[mask_valid]

    print("Tamaño del dataset después de limpieza:", X.shape)
    print("Distribución de la etiqueta DESERTO:\n", y.value_counts(dropna=False))

    # Split con estratificación
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=random_state
    )

    # Pipeline de preprocesado para features numéricos
    numeric_features = X.columns.tolist()
    numeric_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])

    preprocessor = ColumnTransformer(transformers=[
        ("num", numeric_transformer, numeric_features)
    ])

    # Clasificador
    clf = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", RandomForestClassifier(random_state=random_state, class_weight="balanced", n_estimators=200))
    ])

    # (Opcional) GridSearch pequeño — comenta si prefieres entrenamiento directo
    param_grid = {
        "classifier__n_estimators": [100, 200],
        "classifier__max_depth": [None, 10, 20]
    }
    print("Iniciando GridSearchCV (puede tardar) ...")
    grid = GridSearchCV(clf, param_grid, cv=4, scoring="f1", n_jobs=-1, verbose=1)
    grid.fit(X_train, y_train)

    best = grid.best_estimator_
    print("Mejores parámetros:", grid.best_params_)

    # Evaluación
    y_pred = best.predict(X_test)
    y_proba = best.predict_proba(X_test)[:, 1] if hasattr(best, "predict_proba") else None

    print("\nReporte de evaluación (test):")
    print(classification_report(y_test, y_pred))
    if y_proba is not None:
        try:
            auc = roc_auc_score(y_test, y_proba)
            print("ROC AUC:", auc)
        except Exception:
            pass

    # Guardar modelo (pipeline completo) con el nombre que usa la app
    print("Guardando modelo en:", output_model_path)
    joblib.dump(best, output_model_path)
    print("Modelo guardado. Fecha:\n", datetime.datetime.now())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Entrena y guarda modelo de desercion")
    parser.add_argument("--input", default="Notas_1corte.xlsx", help="Ruta al archivo Excel con datos")
    parser.add_argument("--output", default="modelo_desercion.pkl", help="Ruta donde se guardará el modelo")
    args = parser.parse_args()

    build_and_train(args.input, args.output)
