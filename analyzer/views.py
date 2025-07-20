from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import UserCreationForm
from django.http import HttpResponse
from django.template.loader import render_to_string
from weasyprint import HTML
from .forms import URLForm
from .models import URLAnalysis
from . import utils
import json

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'analyzer/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'login.html', {'error': 'Credenciales inválidas'})
    return render(request, 'login.html')

@login_required
def dashboard_view(request):
    form = URLForm()
    history = URLAnalysis.objects.filter(user=request.user).order_by('-date')[:10]
    return render(request, 'analyzer/dashboard.html', {
        'form': form,
        'history': history
    })

@login_required
def url_analysis_view(request):
    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            u = form.cleaned_data['url']
            resultado = utils.veredicto_final(u)

            heur = resultado['detalles']['heuristico']
            ml = resultado['detalles']['ml']
            vt = resultado['detalles']['virustotal']

            analysis = URLAnalysis.objects.create(
                url=u,
                user=request.user,
                heur_score=heur['score'],
                heur_flags=", ".join(heur['flags']),
                ml_prediction=ml['prediccion'],
                ml_probability=ml['probabilidad'],
                vt_malicious=vt['maliciosos'],
                vt_harmless=vt['inofensivos'],
                verdict=resultado['veredicto'],  
                final_score=resultado['puntuacion_total']  
            )
            return redirect('analysis_result', analysis_id=analysis.id)
    return redirect('dashboard')

@login_required
def analysis_result_view(request, analysis_id):
    analysis = get_object_or_404(URLAnalysis, id=analysis_id, user=request.user)
    heur_flags_list = (
        [f.strip() for f in analysis.heur_flags.split(',')] if analysis.heur_flags else []
    )
    return render(request, 'analyzer/index.html', {
        'form': URLForm(initial={'url': analysis.url}),
        'analysis': analysis,
        'ml_pred': analysis.ml_prediction,
        'ml_prob': analysis.ml_probability,
        'vt_malicious': analysis.vt_malicious,
        'vt_harmless': analysis.vt_harmless,
        'verdict': analysis.verdict,
        'heur_flags_list': heur_flags_list,
    })

@login_required
def analysis_dashboard_view(request, analysis_id):
    analysis = get_object_or_404(URLAnalysis, id=analysis_id, user=request.user)
    heur_flags_list = (
        [f.strip() for f in analysis.heur_flags.split(',')] if analysis.heur_flags else []
    )

    score = analysis.heur_score or 0
    ml_prob = (analysis.ml_probability or 0) * 100
    vt_mal = analysis.vt_malicious or 0
    vt_harm = analysis.vt_harmless or 0

    resumen = f"La URL analizada presenta un comportamiento "
    if score >= 3 or ml_prob >= 75 or vt_mal > 5:
        resumen += "ALTAMENTE sospechoso"
    elif score >= 1 or ml_prob >= 40 or vt_mal > 0:
        resumen += "moderadamente sospechoso"
    else:
        resumen += "poco sospechoso"

    resumen += f", con una puntuación heurística de {score}, una probabilidad del {ml_prob:.1f}% según el modelo de ML, "
    resumen += f"{vt_mal} detecciones maliciosas en VirusTotal y {vt_harm} consideradas inofensivas."

    chart_data = json.dumps([score, analysis.ml_probability or 0, vt_mal, vt_harm])

    return render(request, 'analyzer/analysis_dashboard.html', {
        'analysis': analysis,
        'heur_flags_list': heur_flags_list,
        'chart_data': chart_data,
        'resumen_ia': resumen
    })

@login_required
def export_pdf_view(request, analysis_id):
    analysis = get_object_or_404(URLAnalysis, id=analysis_id, user=request.user)
    heur_flags_list = (
        [f.strip() for f in analysis.heur_flags.split(',')] if analysis.heur_flags else []
    )

    score = analysis.heur_score or 0
    ml_prob = (analysis.ml_probability or 0) * 100
    vt_mal = analysis.vt_malicious or 0
    vt_harm = analysis.vt_harmless or 0

    resumen = f"La URL analizada presenta un comportamiento "
    if score >= 3 or ml_prob >= 75 or vt_mal > 5:
        resumen += "ALTAMENTE sospechoso"
    elif score >= 1 or ml_prob >= 40 or vt_mal > 0:
        resumen += "moderadamente sospechoso"
    else:
        resumen += "poco sospechoso"

    resumen += f", con una puntuación heurística de {score}, una probabilidad del {ml_prob:.1f}% según el modelo de ML, "
    resumen += f"{vt_mal} detecciones maliciosas en VirusTotal y {vt_harm} consideradas inofensivas."

    html_string = render_to_string('analyzer/pdf_report.html', {
        'analysis': analysis,
        'heur_flags_list': heur_flags_list,
        'resumen_ia': resumen
    })

    pdf_file = HTML(string=html_string).write_pdf()

    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="informe_{analysis_id}.pdf"'
    return response

@login_required
def executive_report_view(request, analysis_id):
    analysis = get_object_or_404(URLAnalysis, id=analysis_id, user=request.user)
    heur_flags_list = (
        [f.strip() for f in analysis.heur_flags.split(',')] if analysis.heur_flags else []
    )

    # Variables analizadas
    heur_score = analysis.heur_score or 0
    ml_prediction = analysis.ml_prediction or "desconocido"
    ml_prob = (analysis.ml_probability or 0) * 100
    vt_mal = analysis.vt_malicious or 0
    vt_harmless = analysis.vt_harmless or 0

    # Veredicto interpretado (resumen IA)
    conclusion = f"El sistema ha determinado que la URL '{analysis.url}' tiene un comportamiento "

    if heur_score >= 3 or ml_prob >= 75 or vt_mal > 5:
        conclusion += "ALTAMENTE sospechoso"
    elif heur_score >= 1 or ml_prob >= 40 or vt_mal > 0:
        conclusion += "moderadamente sospechoso"
    else:
        conclusion += "poco sospechoso"

    conclusion += f". Esta conclusión se basa en una puntuación heurística de {heur_score}, "
    conclusion += f"una predicción de modelo ML como '{ml_prediction}' con un {ml_prob:.1f}% de confianza, "
    conclusion += f"{vt_mal} motores detectores marcándola como maliciosa y {vt_harmless} como inofensiva."

    # Pasar datos al template
    return render(request, 'analyzer/executive_report.html', {
        'analysis': analysis,
        'heur_flags_list': heur_flags_list,
        'conclusion': conclusion,
        'chart_data': json.dumps([heur_score, ml_prob / 100, vt_mal, vt_harmless])
    })
