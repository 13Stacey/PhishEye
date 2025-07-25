# 🛡️ PhishEye - Analizador de URLs Sospechosas (TFM)

**PhishEye** es un proyecto desarrollado como Trabajo de Fin de Máster (TFM) por Eduardo Bejarano, dentro del Máster en Seguridad de las Tecnologías de la Información y las Comunicaciones.
El objetivo es detectar URLs maliciosas mediante técnicas heurísticas, machine learning y consultas a VirusTotal, todo integrado en una interfaz web sencilla y profesional.

---

## Funcionalidades principales

* ✅ Análisis de URLs con modelo ML personalizado
* ✅ Entrenamiento automático con CSVs (última columna = etiqueta)
* ✅ Generación de informes detallados por análisis
* ✅ Exportación de informes en PDF
* ✅ Registro/login de usuarios
* ✅ Dashboard con histórico de análisis

---

## 🖼️ Vista previa

![image](https://github.com/user-attachments/assets/d3781056-bddb-4c36-b8a9-c6b153b393e6)

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
PhishEye/
├── analyzer/
│   ├── templates/
│   │   └── analyzer/
│   │       ├── base.html
│   │       ├── login.html
│   │       ├── register.html
│   │       ├── dashboard.html
│   │       ├── analysis_dashboard.html
│   │       └── training/train_model.html
│   ├── static/
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── urls.py
│   ├── utils.py
│   └── views.py
├── phishing_checker/
│   ├── __init__.py
│   ├── asgi.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── data/
│   └── (aquí se guardan modelos, escaladores y datasets por usuario)
├── db.sqlite3
├── manage.py
├── README.md
├── requirements.txt
└── venv/  (NO se sube a GitHub)
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

---

## 🧾 Historial de versiones

### v1.1 (Julio 2025)

* Añadido informe ejecutivo inicial tras el análisis de URL.
* Integración básica con exportación a PDF del análisis.
* Vista `dashboard` con histórico de análisis por usuario.
* Interfaz funcional con login y registro de usuarios.
* Estilo base con fondo degradado y diseño claro.

### v1.2 (Julio 2025)

* Commit inicial completo para revisión con Codex.
* Añadida funcionalidad de entrenamiento desde CSV (AutoML).
* Vista `train_model` con métricas y nueva lógica ML.
* Refuerzo del análisis heurístico y visualizaciones en dashboard.
* Rediseño de rutas y templates para exportar e interpretar análisis.

---

## Versión

`v1.2` — Julio 2025

---

## Instalación local

```bash
git clone https://github.com/13Stacey/PhishEye.git
cd PhishEye
python -m venv venv
venv\Scripts\activate  # En Windows
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

---

🐳 Despliegue con Docker
Puedes ejecutar PhishEye en un contenedor Docker que ya incluye todas sus dependencias, incluido WeasyPrint para la generación de PDFs. Es ideal si no quieres instalar nada más en tu sistema.

🔧 Requisitos
Docker

Docker Compose

▶️ Instrucciones de uso
Clona el repositorio:


git clone https://github.com/13Stacey/PhishEye.git
cd PhishEye
Crea un archivo .env con tu clave de API de VirusTotal:

VIRUSTOTAL_API_KEY=TU_API_KEY

Levanta la aplicación:

docker-compose up --build

Accede desde el navegador:

http://localhost:8000

🐳 Despliegue para producción
Si deseas un entorno más optimizado, puedes usar el archivo docker-compose.prod.yml, que emplea Gunicorn como servidor WSGI:

docker-compose -f docker-compose.prod.yml up --build
