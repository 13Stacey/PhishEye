from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .forms import URLForm
from .models import URLAnalysis
from . import utils

@login_required
def url_analysis_view(request):
    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            u = form.cleaned_data['url']

            # Análisis heurístico
            hs, hf = utils.analisis_heuristico(u)

            # Clasificación con ML
            ml_pred, ml_prob = utils.clasificar_url_ml(u)

            # Análisis con VirusTotal
            vt_malicious, vt_harmless = utils.consultar_virustotal(u)

            # Veredicto combinado
            if ml_pred == 'phishing' or hs >= 2 or (vt_malicious and vt_malicious > 0):
                verdict = "Sospechoso"
            else:
                verdict = "Legítimo"

            # Guardar análisis en la base de datos
            analysis = URLAnalysis.objects.create(
                url=u,
                user=request.user,
                heur_score=hs,
                heur_flags=", ".join(hf),
                vt_malicious=vt_malicious,
                vt_harmless=vt_harmless,
                ml_prediction=ml_pred,
                ml_probability=ml_prob,
                verdict=verdict
            )

            return redirect('analysis_result', analysis_id=analysis.id)
    else:
        form = URLForm()

    return render(request, 'analyzer/index.html', {'form': form})

@login_required
def analysis_result_view(request, analysis_id):
    analysis = get_object_or_404(URLAnalysis, id=analysis_id, user=request.user)
    return render(request, 'analyzer/index.html', {
        'form': URLForm(initial={'url': analysis.url}),
        'analysis': analysis,
        'ml_pred': analysis.ml_prediction,
        'ml_prob': analysis.ml_probability
    })
