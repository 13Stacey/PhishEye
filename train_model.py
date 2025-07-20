import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# ============================
# CONFIGURACIÓN DE RUTA
# ============================
dataset_path = os.path.join("data", "dataset_phishing.csv")

# ============================
# CARGA Y PREPARACIÓN DEL DATASET
# ============================
df = pd.read_csv(dataset_path)

# Selección de columnas del dataset original
features = [
    'length_url', 'nb_dots', 'nb_hyphens', 'nb_at', 'https_token',
    'ip', 'ratio_digits_url', 'prefix_suffix', 'phish_hints', 'domain_age'
]

# Preparamos DataFrame con copia segura
df = df[features + ['status']].copy()
df.dropna(inplace=True)

# Mapeamos la etiqueta textual a binaria
df['label'] = df['status'].map({'legitimate': 0, 'phishing': 1})

X = df[features]
y = df['label']

# ============================
# ESCALADO Y DIVISIÓN DE DATOS
# ============================
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

# ============================
# ENTRENAMIENTO DEL MODELO
# ============================
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ============================
# EVALUACIÓN
# ============================
y_pred = model.predict(X_test)
print("\n✅ Informe de clasificación:")
print(classification_report(y_test, y_pred))
print("🔢 Exactitud total:", round(accuracy_score(y_test, y_pred) * 100, 2), "%")

# ============================
# GUARDADO DEL MODELO Y SCALER
# ============================
joblib.dump(model, 'ml_model.pkl')
joblib.dump(scaler, 'scaler.pkl')

print("\n📦 Modelo y scaler guardados como:")
print(" - ml_model.pkl")
print(" - scaler.pkl")
