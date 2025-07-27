from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import ScanSession

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)
    
    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email", "password1", "password2")
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        user.first_name = self.cleaned_data["first_name"]
        user.last_name = self.cleaned_data["last_name"]
        if commit:
            user.save()
        return user

class GitScanForm(forms.Form):
    repository_url = forms.URLField(
        label="Git Repository URL",
        widget=forms.URLInput(attrs={
            'class': 'form-control',
            'placeholder': 'https://github.com/username/repository.git'
        }),
        help_text="Enter the URL of the Git repository to scan"
    )
    
class GitDeepScanForm(forms.Form):
    repository_url = forms.URLField(
        label="Git Repository URL",
        widget=forms.URLInput(attrs={
            'class': 'form-control',
            'placeholder': 'https://github.com/username/repository.git'
        }),
        help_text="Enter the URL of the Git repository for deep scan (all commits)"
    )
    max_commits = forms.IntegerField(
        label="Maximum Commits to Scan",
        initial=100,
        min_value=1,
        max_value=1000,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': '100'
        }),
        help_text="Limit the number of commits to scan (1-1000)"
    )

class ZipUploadForm(forms.Form):
    zip_file = forms.FileField(
        label="Upload ZIP file",
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.zip'
        }),
        help_text="Upload a ZIP file containing your repository code (max 50MB)"
    )
    
    def clean_zip_file(self):
        zip_file = self.cleaned_data.get('zip_file')
        if zip_file:
            if not zip_file.name.endswith('.zip'):
                raise forms.ValidationError("Please upload a ZIP file.")
            if zip_file.size > 50 * 1024 * 1024:  # 50MB
                raise forms.ValidationError("File size must be under 50MB.")
        return zip_file

class ContactForm(forms.Form):
    name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    subject = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    message = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 5})
    )
