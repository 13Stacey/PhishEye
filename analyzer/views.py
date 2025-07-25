from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.http import HttpResponse
from django.template.loader import render_to_string
from .forms import URLForm, UploadDatasetForm
from .models import URLAnalysis
import pandas as pd
import os
import joblib
import json
from weasyprint import HTML
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score


def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('dashboard')
    else:
        form = UserCreationForm()
    return render(request, 'analyzer/register.html', {'form': form})


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
            # Simulación de análisis ficticio
            heur_score = 3
            ml_prediction = "malicious"
            ml_probability = 0.85
            vt_malicious = 5
            vt_harmless = 20
            final_score = heur_score + round(ml_probability * 10) + vt_malicious

            analysis = URLAnalysis.objects.create(
                url=u,
                user=request.user,
                heur_score=heur_score,
                heur_flags="long_url, suspicious_word",
                ml_prediction=ml_prediction,
                ml_probability=ml_probability,
                vt_malicious=vt_malicious,
                vt_harmless=vt_harmless,
                verdict="malicious",
                final_score=final_score
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

    resumen += f", con una puntuación heurística de {score}, una probabilidad del {ml_prob:.1f}%, "
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

    resumen = f"Resumen del análisis de la URL {analysis.url} con puntuación heurística {analysis.heur_score}"

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

    heur_score = analysis.heur_score or 0
    ml_prediction = analysis.ml_prediction or "desconocido"
    ml_prob = (analysis.ml_probability or 0) * 100
    vt_mal = analysis.vt_malicious or 0
    vt_harmless = analysis.vt_harmless or 0

    conclusion = f"La URL '{analysis.url}' tiene un comportamiento "

    if heur_score >= 3 or ml_prob >= 75 or vt_mal > 5:
        conclusion += "ALTAMENTE sospechoso"
    elif heur_score >= 1 or ml_prob >= 40 or vt_mal > 0:
        conclusion += "moderadamente sospechoso"
    else:
        conclusion += "poco sospechoso"

    conclusion += f". Puntuación heurística: {heur_score}, modelo ML: {ml_prediction} con {ml_prob:.1f}% de confianza, "
    conclusion += f"{vt_mal} motores lo marcan como malicioso, {vt_harmless} lo consideran seguro."

    return render(request, 'analyzer/executive_report.html', {
        'analysis': analysis,
        'heur_flags_list': heur_flags_list,
        'conclusion': conclusion,
        'chart_data': json.dumps([heur_score, ml_prob / 100, vt_mal, vt_harmless])
    })


@login_required
def train_model_view(request):
    metrics = None

    if request.method == 'POST':
        form = UploadDatasetForm(request.POST, request.FILES)

        if form.is_valid():
            csv_file = form.cleaned_data['file']

            try:
                df = pd.read_csv(csv_file)

                if df.shape[1] < 2:
                    return render(request, 'analyzer/training/train_model.html', {
                        'form': form,
                        'error': 'El CSV debe tener al menos una columna de etiquetas y una de características.'
                    })

                X = df.iloc[:, :-1]
                y = df.iloc[:, -1]
                X = X.select_dtypes(include=['number'])

                if X.empty:
                    return render(request, 'analyzer/training/train_model.html', {
                        'form': form,
                        'error': 'El dataset no contiene columnas numéricas para entrenamiento.'
                    })

                df_clean = pd.concat([X, y], axis=1).dropna()
                X = df_clean.iloc[:, :-1]
                y = df_clean.iloc[:, -1]

                scaler = MinMaxScaler()
                X_scaled = scaler.fit_transform(X)
                X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

                model = RandomForestClassifier(n_estimators=100, random_state=42)
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)

                metrics = {
                    'accuracy': round(accuracy_score(y_test, y_pred), 2),
                    'precision': round(precision_score(y_test, y_pred, average='weighted', zero_division=0), 2),
                    'recall': round(recall_score(y_test, y_pred, average='weighted', zero_division=0), 2),
                    'samples': len(df_clean)
                }

                user_prefix = f"user_{request.user.id}"
                os.makedirs('data', exist_ok=True)
                joblib.dump(model, os.path.join('data', f'{user_prefix}_model.pkl'))
                joblib.dump(scaler, os.path.join('data', f'{user_prefix}_scaler.pkl'))
                df_clean.to_csv(os.path.join('data', f'{user_prefix}_dataset.csv'), index=False)

                request.session['custom_model'] = os.path.join('data', f'{user_prefix}_model.pkl')
                request.session['custom_scaler'] = os.path.join('data', f'{user_prefix}_scaler.pkl')
                request.session.modified = True

            except Exception as e:
                return render(request, 'analyzer/training/train_model.html', {
                    'form': form,
                    'error': f'Ocurrió un error al procesar el CSV: {e}'
                })
    else:
        form = UploadDatasetForm()

    return render(request, 'analyzer/training/train_model.html', {
        'form': form,
        'metrics': metrics
    })
