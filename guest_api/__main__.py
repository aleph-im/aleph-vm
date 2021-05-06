import logging
from aiohttp import web

logging.basicConfig(level=logging.DEBUG)


async def hello(request):
    return web.json_response({"Hello": "From API"})


def run_guest_api(unix_socket_path):
    app = web.Application()
    app.router.add_get('/get', hello)
    web.run_app(app=app, path=unix_socket_path)
