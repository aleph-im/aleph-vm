from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from .views import ArticleListView, CommentFormView, test_view

urlpatterns = [
    path("", ArticleListView.as_view(), name="article-list"),
    path("comment", csrf_exempt(CommentFormView.as_view()), name="comment"),
    path("post", csrf_exempt(test_view), name="test-post"),
]
