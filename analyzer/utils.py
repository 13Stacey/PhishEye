import re
import os
import joblib
import requests
from urllib.parse import urlparse
from django.conf import settings

# ==========================
# Palabras clave sospechosas
# ==========================
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "account", "update", "verify", "bank", "confirm",
    "ebay", "webscr", "paypal"
]

# ==========================
# Análisis Heurístico
# ==========================
def analisis_heuristico(url):
    flags = []
    score = 0
    max_score = 10

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if len(url) > 100:
        score += 1
        flags.append(f"URL muy larga ({len(url)} caracteres)")

    if hostname.count('.') >= 3:
        score += 1
        flags.append(f"Demasiados subdominios ({hostname.count('.') + 1} niveles)")

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        score += 2
        flags.append("Dominio es una IP")

    if "@" in url:
        score += 1
        flags.append("Contiene '@' (técnica de ofuscación)")

    if parsed.scheme != "https":
        score += 1
        flags.append("No usa HTTPS")

    if parsed.port and parsed.port not in [80, 443]:
        score += 1
        flags.append(f"Puerto inusual: {parsed.port}")

    if re.search(r'[A-Z]', url):
        score += 1
        flags.append("Contiene letras mayúsculas")

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url.lower():
            score += 2
            flags.append(f"Palabra sospechosa: \"{kw}\"")
            break

    normalized_score = round(score / max_score, 2)
    return normalized_score, flags

# ==========================
# Clasificador de URL con ML
# ==========================
model_path = os.path.join(os.path.dirname(__file__), 'ml_model.pkl')
scaler_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scaler.pkl")

model = joblib.load(model_path)
scaler = joblib.load(scaler_path)

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    length_url = len(url)
    nb_dots = url.count('.')
    nb_hyphens = url.count('-')
    nb_at = url.count('@')
    https_token = int('https' in parsed.path.lower() or 'https' in hostname.lower() or 'https' in parsed.query.lower())
    is_ip = int(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) is not None)
    digit_count = sum(c.isdigit() for c in url)
    ratio_digits_url = round(digit_count / length_url, 2) if length_url > 0 else 0
    prefix_suffix = int('-' in hostname)
    phish_hints = int(any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS))
    domain_age = -1

    return [
        length_url,
        nb_dots,
        nb_hyphens,
        nb_at,
        https_token,
        is_ip,
        ratio_digits_url,
        prefix_suffix,
        phish_hints,
        domain_age
    ]

def clasificar_url_ml(url):
    features = [extract_features(url)]
    features = scaler.transform(features)
    pred = model.predict(features)[0]
    prob = model.predict_proba(features)[0].max()
    return pred, round(prob, 2)

# ==========================
# Consulta a VirusTotal
# ==========================
def consultar_virustotal(url):
    api_key = settings.VIRUSTOTAL_API_KEY
    headers = {"x-apikey": api_key}

    try:
        scan_url = "https://www.virustotal.com/api/v3/urls"
        resp = requests.post(scan_url, headers=headers, data={"url": url}, timeout=5)
        if resp.status_code != 200:
            print(f"[VT] Error en el envío: {resp.status_code}")
            return None, None

        resource_id = resp.json().get("data", {}).get("id")
        if not resource_id:
            print("[VT] No se obtuvo ID del análisis")
            return None, None

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

# ==========================
# Veredicto Final
# ==========================
def veredicto_final(url):
    heur_score, heur_flags = analisis_heuristico(url)
    ml_pred, ml_prob = clasificar_url_ml(url)
    vt_malicious, vt_harmless = consultar_virustotal(url)

    if vt_malicious is not None and vt_harmless is not None:
        total = vt_malicious + vt_harmless
        vt_score = vt_malicious / total if total > 0 else 0
    else:
        vt_score = 0

    final_score = round(0.4 * heur_score + 0.4 * ml_prob + 0.2 * vt_score, 2)
    veredicto = "malicioso" if final_score >= 0.6 else "legítimo"

    return {
        "veredicto": veredicto,
        "puntuacion_total": final_score,
        "detalles": {
            "heuristico": {
                "score": heur_score,
                "flags": heur_flags
            },
            "ml": {
                "prediccion": "malicioso" if ml_pred == 1 else "legítimo",
                "probabilidad": ml_prob
            },
            "virustotal": {
                "maliciosos": vt_malicious,
                "inofensivos": vt_harmless,
                "score": round(vt_score, 2)
            }
        }
    }
