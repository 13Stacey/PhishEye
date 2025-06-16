from django import forms

class URLForm(forms.Form):
    url = forms.URLField(label='',
        widget=forms.URLInput(attrs={
            'placeholder': 'https://www.ejemplo.com',
            'class': 'url-input-field'
        }))