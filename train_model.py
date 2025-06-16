import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
import joblib

# Cargar dataset
df = pd.read_csv('data/malicious_phish.csv')
df = df[['url', 'type']]  # Nos quedamos solo con estas dos columnas
df = df[df['type'].isin(['phishing', 'benign'])]  # Aseguramos tipos válidos

# Normalizar etiquetas
df['label'] = df['type'].apply(lambda x: 'phishing' if x == 'phishing' else 'legítimo')

# Función para extraer características simples desde una URL
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    features = [
        len(url),
        len(re.findall(r'\d', url)),
        1 if re.match(r'^\d+(\.\d+){3}$', hostname) else 0,
        url.count('@') + url.count('-'),
        1 if any(kw in url.lower() for kw in ['login','secure','account','update','verify','bank','signin']) else 0
    ]
    return features

# Extraer X e y
X = [extract_features(u) for u in df['url']]
y = df['label']

# Entrenar modelo
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X, y)

# Evaluar
print("Precisión en entrenamiento:", clf.score(X, y))

# Guardar modelo
joblib.dump(clf, 'analyzer/ml_model.pkl')
print("Modelo guardado en analyzer/ml_model.pkl")
