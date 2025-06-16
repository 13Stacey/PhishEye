from django.urls import path
from . import views

urlpatterns = [
    path('', views.url_analysis_view, name='home'),
    path('resultado/<int:analysis_id>/', views.analysis_result_view, name='analysis_result'),
]
