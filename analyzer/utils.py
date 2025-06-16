import re
import os
import joblib
import requests
from urllib.parse import urlparse
from django.conf import settings

# Palabras clave sospechosas
SUSPICIOUS_KEYWORDS = ["login", "signin", "secure", "account", "update", "verify", "bank", "confirm"]

# ==========================
# ANÁLISIS HEURÍSTICO
# ==========================
def analisis_heuristico(url):
    flags = []
    score = 0

    if len(url) > 100:
        score += 1
        flags.append(f"Longitud muy larga ({len(url)} caracteres)")

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if hostname.count('.') >= 3:
        score += 1
        flags.append(f"Múltiples subdominios ({hostname.count('.') + 1} niveles)")

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        score += 1
        flags.append("Dominio es una IP")

    if "@" in url:
        score += 1
        flags.append("Contiene '@'")

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url.lower():
            score += 1
            flags.append(f"Contiene palabra sospechosa: \"{kw}\"")
            break

    return score, flags

# ==========================
# CLASIFICADOR MACHINE LEARNING
# ==========================
model_path = os.path.join(os.path.dirname(__file__), 'ml_model.pkl')
model = joblib.load(model_path)

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    features = [
        len(url),
        len(re.findall(r'\d', url)),
        1 if re.match(r'^\d+(\.\d+){3}$', hostname) else 0,
        url.count('@') + url.count('-'),
        1 if any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS) else 0
    ]
    return features

def clasificar_url_ml(url):
    features = [extract_features(url)]
    pred = model.predict(features)[0]
    prob = model.predict_proba(features)[0].max()
    return pred, round(prob, 2)

# ==========================
# CONSULTA A VIRUSTOTAL
# ==========================
def consultar_virustotal(url):
    api_key = settings.VIRUSTOTAL_API_KEY
    headers = {
        "x-apikey": api_key
    }

    try:
        # Paso 1: enviar URL para obtener ID
        scan_url = "https://www.virustotal.com/api/v3/urls"
        resp = requests.post(scan_url, headers=headers, data={"url": url}, timeout=5)

        if resp.status_code != 200:
            print(f"[VT] Error en el envío: {resp.status_code}")
            return None, None

        resource_id = resp.json().get("data", {}).get("id")
        if not resource_id:
            print("[VT] No se obtuvo ID del análisis")
            return None, None

        # Paso 2: consultar análisis usando ID
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{resource_id}"
        result = requests.get(analysis_url, headers=headers, timeout=5)

        if result.status_code != 200:
            print(f"[VT] Error al consultar análisis: {result.status_code}")
            return None, None

        stats = result.json().get("data", {}).get("attributes", {}).get("stats", {})
        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)

        return malicious, harmless

    except Exception as e:
        print(f"[VT ERROR] {e}")
        return None, None
