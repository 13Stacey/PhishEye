from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('analyzer.urls')),  # Aquí se incluyen TODAS las vistas de analyzer
]
