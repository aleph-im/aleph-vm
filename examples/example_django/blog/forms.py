from django import forms
from django.forms import ModelForm

from .models import Comment


class CommentForm(ModelForm):
    class Meta:
        model = Comment
        fields = ["text", "article"]
        widgets = {"article": forms.HiddenInput()}
