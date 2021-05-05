from os import system
import logging
from aiohttp import web

logging.basicConfig(level=logging.DEBUG)


async def hello(request):
    system("chown jailman:jailman /srv/jailer/firecracker/5/root/tmp/v.sock_53")
    return web.Response(text="Hello, world")

app = web.Application()
app.router.add_get('/', hello)

web.run_app(app=app, path='/srv/jailer/firecracker/5/root/tmp/v.sock_53')
