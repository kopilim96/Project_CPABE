
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import User, Specialist

# For Login
class UserLoginForm(forms.Form):
    USER_TYPE_CHOICES = (
        ('Admin', 'Admin'),
        ('CA', 'CA'),
        ('Doctor', 'Doctor'),
        ('Patient', 'Patient'),
    )
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    user_type = forms.ChoiceField(choices=USER_TYPE_CHOICES)

# For Register
class RegisterForm(forms.ModelForm):
    user_type = forms.ChoiceField(choices=[('Doctor', 'Doctor'), ('Patient', 'Patient')], required=True)
    specialist = forms.CharField(max_length=100, required=True, label="Specialist")
    
    class Meta:
        model = User
        fields = [
            'username', 
            'password', 
            'common_name', 
            'country', 
            'state', 
            'locality', 
            'organization', 
            'organizational_unit', 
            'email',
            'specialist'
        ]

# File Upload
class FileUploadForm(forms.Form):
    file = forms.FileField(label='Upload File')
    patient = forms.ModelChoiceField(queryset=None, label='Select Patient')

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user')  # The current logged-in doctor is passed in the kwargs
        super(FileUploadForm, self).__init__(*args, **kwargs)

        # Only patients with the same specialization as the doctor are shown in the dropdown
        self.fields['patient'].queryset = User.objects.filter(
            specialist__specialization=user.specialist.specialization,
            specialist__is_doctor=False
        )
        
