# 🐳 PhishEye - Docker Deployment

Este documento explica cómo desplegar **PhishEye** en un entorno Docker, tanto en desarrollo como en producción, utilizando `docker-compose`.

---

## 📦 Requisitos

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- Clave API de VirusTotal

---

## ▶️ Modo desarrollo

Este modo usa el servidor de desarrollo de Django y es ideal para pruebas locales.

### 1. Clona el repositorio:

```bash
git clone https://github.com/13Stacey/PhishEye.git
cd PhishEye
```

### 2. Crea el archivo `.env`:

```env
VIRUSTOTAL_API_KEY=tu_clave_de_virustotal
```

### 3. Ejecuta el entorno:

```bash
docker-compose up --build
```

### 4. Accede a la aplicación:

[http://localhost:8000](http://localhost:8000)

---

## 🔐 Modo producción (con Gunicorn)

Este modo es más robusto para entornos reales de despliegue.

### 1. Asegúrate de tener `gunicorn` en `requirements.txt`:

```bash
pip install gunicorn
pip freeze > requirements.txt
```

### 2. Ejecuta con configuración de producción:

```bash
docker-compose -f docker-compose.prod.yml up --build
```

---

## 🐋 Subida de imagen a DockerHub

Puedes construir y subir tu imagen con los siguientes comandos:

```bash
docker login
docker tag phisheye:latest 13stacey/phisheye:1.0
docker push 13stacey/phisheye:1.0
```

---

## 📥 Descargar desde DockerHub

Una vez publicada, cualquier usuario puede hacer:

```bash
docker pull 13stacey/phisheye:1.0
docker run -d -p 8000:8000 13stacey/phisheye:1.0
```

---

## 📁 Volumen de datos

El contenedor monta automáticamente la carpeta `./data` en `/app/data`, donde se guardan datasets, modelos y otros archivos por usuario.

---

## ✅ Estado

- [x] Compatible con `WeasyPrint`
- [x] Soporte para API de VirusTotal mediante `.env`
- [x] Despliegue con Gunicorn listo para producción

---

## 🙋 Autor

**Eduardo Bejarano Rúa**  
Cybersecurity & Digital Forensics  
GitHub: [13Stacey](https://github.com/13Stacey)
