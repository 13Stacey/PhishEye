from django.contrib import admin
from django.urls import path
from analyzer import views as analyzer_views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),

    # Autenticación
    path('', auth_views.LoginView.as_view(template_name='analyzer/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('register/', analyzer_views.register_view, name='register'),

    # Funcionalidad principal
    path('dashboard/', analyzer_views.dashboard_view, name='dashboard'),
    path('analyze/', analyzer_views.url_analysis_view, name='analyze_url'),
    path('result/<int:analysis_id>/', analyzer_views.analysis_result_view, name='analysis_result'),
    path('dashboard/<int:analysis_id>/', analyzer_views.analysis_dashboard_view, name='analysis_dashboard'),
    path('export/<int:analysis_id>/', analyzer_views.export_pdf_view, name='export_pdf'),
    path('informe/<int:analysis_id>/', analyzer_views.executive_report_view, name='executive_report'),

]
