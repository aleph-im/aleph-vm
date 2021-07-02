import os

from django.http import JsonResponse
from django.views.generic import ListView, FormView, CreateView

from .forms import CommentForm
from .models import Article


class ArticleListView(ListView):
    model = Article
    ordering = "-date"

    extra_context = {"form": CommentForm}


class CommentFormView(CreateView):
    template_name = "blog/comment.html"
    form_class = CommentForm
    success_url = "/"


def test_view(request):
    print(request.POST)
    return JsonResponse(request.POST)
