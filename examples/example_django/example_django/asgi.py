"""
ASGI config for example_django project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "example_django.settings")

application = get_asgi_application()

os.system("/usr/bin/python3 /opt/code/manage.py migrate")

os.system("/usr/bin/python3 /opt/code/manage.py loaddata /opt/code/blog/fixtures/default_articles.json")
