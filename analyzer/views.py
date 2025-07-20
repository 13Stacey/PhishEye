from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import UserCreationForm
from .forms import URLForm
from .models import URLAnalysis
from . import utils

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

            # Extraer datos del análisis
            heur = resultado['detalles']['heuristico']
            ml = resultado['detalles']['ml']
            vt = resultado['detalles']['virustotal']

            # Guardar en base de datos
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
    # Divide la cadena de heur_flags en una lista (gestiona None/empty)
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
        'heur_flags_list': heur_flags_list,   # <--- añade esto al contexto
    })
