from django import forms
from .models import UserProfile, Project


class UserProfileForm(forms.ModelForm):
    bio = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"placeholder": "Tell us more about you", "class": "form-control"}),
    )
    picture_file = forms.ClearableFileInput(attrs={"class": "form-control"})

    class Meta:
        model = UserProfile
        fields = ["bio", "picture_file"]


class ProjectForm(forms.ModelForm):
    name = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "A descriptive name", "class": "form-control"})
    )
    picture_file = forms.ClearableFileInput(attrs={"class": "form-control"})
    budget = forms.IntegerField(widget=forms.NumberInput(attrs={"class": "form-control"}))
    members = forms.ModelMultipleChoiceField(
        queryset=UserProfile.objects.all(), widget=forms.CheckboxSelectMultiple()
    )

    class Meta:
        model = Project
        fields = ["name", "picture_file", "budget", "members"]
