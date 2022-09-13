from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Username", "class": "form-control"})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"placeholder": "Password", "class": "form-control"})
    )


class SignUpForm(UserCreationForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "A unique username", "class": "form-control"})
    )
    email = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Your email address", "class": "form-control"})
    )
    first_name = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Your first name", "class": "form-control"})
    )
    last_name = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Your last name", "class": "form-control"})
    )
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"placeholder": "Password", "class": "form-control"}),
    )
    password2 = forms.CharField(
        label="Password check",
        widget=forms.PasswordInput(attrs={"placeholder": "Retype your password", "class": "form-control"}),
    )

    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name", "password1", "password2")


class ResetForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Your username", "class": "form-control"})
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"placeholder": "Your email address", "class": "form-control"})
    )
    # old_password = forms.CharField(
    #     label="Old Password",
    #     widget=forms.PasswordInput(attrs={"placeholder": "Old password", "class": "form-control"}),
    # )
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"placeholder": "A new password", "class": "form-control"}),
    )
    password2 = forms.CharField(
        label="Password check",
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "Retype your new password",
                "class": "form-control",
            },
        ),
    )
