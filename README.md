# 🛡️ PhishEye - Analizador de URLs Sospechosas (TFM)

**PhishEye** es un proyecto desarrollado como Trabajo de Fin de Máster (TFM) por Eduardo Bejarano, dentro del Máster en Seguridad de las Tecnologías de la Información y las Comunicaciones.  
El objetivo es detectar URLs maliciosas mediante técnicas heurísticas, machine learning y consultas a VirusTotal, todo integrado en una interfaz web sencilla y profesional.

---

## 🔍 Funcionalidades

- 🧠 **Análisis heurístico**: identifica patrones sospechosos en la URL (IP en dominio, uso de `@`, subdominios, palabras clave como `login`, `secure`, etc.).
- 🤖 **Clasificación con Machine Learning**: predicción entrenada con dataset real etiquetado.
- ☣️ **Consulta a VirusTotal**: verificación de reputación real mediante su API pública.
- 💾 **Almacenamiento en base de datos**: guarda el análisis, el usuario y los indicadores detectados.
- 🔐 **Login requerido**: solo usuarios autenticados pueden usar el sistema.

---

## 🖼️ Vista previa

> *(Aquí puedes añadir una captura de pantalla del análisis completo, cuando quieras.)*

---

## 🚀 Instalación

1. Clona el repositorio:

```bash
git clone https://github.com/13Stacey/PhishEye.git
cd PhishEye
```

2. Crea entorno virtual y actívalo:

```bash
python -m venv venv
venv\Scripts\activate
```

3. Instala dependencias:

```bash
pip install -r requirements.txt
```

4. Configura tu clave de VirusTotal en `settings.py`:

```python
VIRUSTOTAL_API_KEY = "tu_clave_aquí"
```

5. Ejecuta migraciones y lanza el servidor:

```bash
python manage.py makemigrations analyzer
python manage.py migrate
python manage.py runserver
```

---

## 🧪 Prueba

Una vez el servidor esté corriendo, accede a:  
`http://127.0.0.1:8000/`  
y realiza un análisis introduciendo una URL.

---

## 📦 Modelo de Machine Learning

⚠️ Debido al tamaño del modelo `ml_model.pkl`, **no se incluye directamente en el repositorio** por políticas de GitHub. Puedes subir el tuyo o generar uno nuevo a partir del dataset original.

---

## 📁 Estructura del proyecto

```
phishing_checker/
├── analyzer/
│   ├── migrations/
│   ├── templates/analyzer/
│   ├── static/
│   ├── models.py
│   ├── forms.py
│   ├── utils.py
│   └── views.py
├── phishing_checker/
│   └── settings.py
├── db.sqlite3
└── manage.py
```

---

## 🙋 Autor

**Eduardo Bejarano Rua**  
Cybersecurity & Digital Forensics | Universidad Europea  
GitHub: [13Stacey](https://github.com/13Stacey)

---

## 🏁 Estado del proyecto

✅ Versión estable `v1.0`  
🛠️ Se está trabajando en la integración avanzada de VirusTotal y mejoras visuales

---

## 🧠 Licencia

Este proyecto se entrega como parte de un TFM académico y puede ser reutilizado con fines educativos y no comerciales. Para más información, contacta con el autor.
