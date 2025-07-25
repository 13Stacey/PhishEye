from django import forms

class URLForm(forms.Form):
    url = forms.URLField(
        label='',
        widget=forms.URLInput(attrs={
            'placeholder': 'https://www.ejemplo.com',
            'class': 'form-control'  # <-- cambiaste 'url-input-field' por 'form-control'
        })
    )

class UploadDatasetForm(forms.Form):
    file = forms.FileField(label='Dataset CSV')

class SelectURLForm(forms.Form):
    url = forms.ChoiceField(label='Selecciona URL')
