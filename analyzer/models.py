from django.db import models
from django.contrib.auth.models import User

class URLAnalysis(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    url = models.URLField("URL analizada")
    date = models.DateTimeField("Fecha de análisis", auto_now_add=True)

    heur_score = models.IntegerField("Puntuación heurística", null=True, blank=True)
    heur_flags = models.TextField("Indicadores heurísticos detectados", null=True, blank=True)

    vt_malicious = models.IntegerField("Detecciones VT (maliciosas)", null=True, blank=True)
    vt_harmless = models.IntegerField("Detecciones VT (benignas)", null=True, blank=True)

    ml_prediction = models.CharField("Predicción ML", max_length=20, null=True, blank=True)
    ml_probability = models.FloatField("Probabilidad ML", null=True, blank=True)

    verdict = models.CharField("Veredicto global", max_length=50, null=True, blank=True)

    def __str__(self):
        return f"[{self.date:%Y-%m-%d %H:%M}] {self.url} -> {self.verdict}"
