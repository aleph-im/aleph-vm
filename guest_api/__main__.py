import aiohttp
from aiohttp import web


ALEPH_API_SERVER = "https://api2.aleph.im/"


async def proxy(request):
    path = request.match_info.get('tail')
    query_string = request.rel_url.query_string
    url = f"{ALEPH_API_SERVER}{path}?{query_string}"

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            data = await response.read()
            return web.Response(body=data,
                                status=response.status,
                                content_type=response.content_type)


def run_guest_api(unix_socket_path):
    app = web.Application()
    app.router.add_route(method='GET', path='/{tail:.*}', handler=proxy)
    web.run_app(app=app, path=unix_socket_path)


if __name__ == '__main__':
    run_guest_api("/tmp/guest-api")
