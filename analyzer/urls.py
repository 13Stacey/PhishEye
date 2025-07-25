from django.urls import path
from analyzer import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', auth_views.LoginView.as_view(template_name='analyzer/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('register/', views.register_view, name='register'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('analyze/', views.url_analysis_view, name='analyze_url'),
    path('result/<int:analysis_id>/', views.analysis_result_view, name='analysis_result'),
    path('dashboard/<int:analysis_id>/', views.analysis_dashboard_view, name='analysis_dashboard'),
    path('export/<int:analysis_id>/', views.export_pdf_view, name='export_pdf'),
    path('informe/<int:analysis_id>/', views.executive_report_view, name='executive_report'),
    path('train/', views.train_model_view, name='train_model'),  # <- ¡ESTA ES LA RUTA QUE FALTABA!
]
