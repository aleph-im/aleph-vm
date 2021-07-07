import uuid

from django.db import models


class Article(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=256, help_text="Title of the blog article")
    body = models.TextField(help_text="Body of the blog article")
    date = models.DateTimeField(auto_created=True)

    def __str__(self):
        return f"Blog article '{self.title}'"


class Comment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    text = models.CharField(max_length=1024)
    article = models.ForeignKey(to=Article, on_delete=models.CASCADE)
    date = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return f"Comment on {self.article.title}"
