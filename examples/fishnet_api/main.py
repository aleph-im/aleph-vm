import asyncio
import logging
import os
from os import listdir

logger = logging.getLogger(__name__)

logger.debug("import aiohttp")
import aiohttp

logger.debug("import aleph_client")
from aleph_client.vm.cache import VmCache
from aleph_client.vm.app import AlephApp

logger.debug("import aars")
from aars import AARS

logger.debug("import fastapi")
from fastapi import FastAPI, WebSocket

logger.debug("import models")
from .model import *

logger.debug("imports done")

http_app = FastAPI()
app = AlephApp(http_app=http_app)
cache = VmCache()
aars = AARS(channel="FISHNET_TEST")


@app.get("/")
async def index():
    if os.path.exists("/opt/venv"):
        opt_venv = list(listdir("/opt/venv"))
    else:
        opt_venv = []
    return {
        "vm_name": "fishnet_api",
        "endpoints": ["/timeseries/upload",
                      "/datasets", "/user/{address}/datasets", "/datasets/upload",
                      "/algorithms", "/user/{address}/algorithms", "/algorithms/upload",
                      "/executions", "/user/{address}/executions"],
        "files_in_volumes": {
            "/opt/venv": opt_venv,
        },
    }


@app.post("/timeseries/upload")
async def upload_timeseries(timeseries: List[Timeseries]) -> List[Timeseries]:
    created_timeseries = await asyncio.gather(
        *[Timeseries.create(**dict(ts)) for ts in timeseries]
    )
    return [ts for ts in created_timeseries if not isinstance(ts, BaseException)]


@app.get("/datasets")
async def datasets() -> List[Dataset]:
    return await Dataset.fetch_all()


@app.get("/user/{address}/datasets")
async def get_user_datasets(address: str) -> List[Dataset]:
    return await Dataset.query(owner=address)


@app.post("/datasets/upload")
async def upload_dataset(dataset: Dataset) -> Dataset:
    if dataset.ownsAllTimeseries:
        # check if _really_ owns all timeseries
        timeseries = await Timeseries.get(dataset.timeseriesIDs)
        dataset.ownsAllTimeseries = all([ts.owner == dataset.owner for ts in timeseries])
    return await dataset.upsert()


@app.get("/algorithms")
async def get_algorithms() -> List[Algorithm]:
    return await Algorithm.fetch_all()


@app.get("/user/{address}/algorithms")
async def get_user_algorithms(address: str) -> List[Algorithm]:
    return await Algorithm.query(owner=address)


@app.post("/algorithms/upload")
async def upload_algorithm(algorithm: Algorithm) -> Algorithm:
    return await algorithm.upsert()


@app.get("/executions")
async def get_executions() -> List[Execution]:
    return await Execution.fetch_all()


@app.get("/user/{address}/executions")
async def get_user_executions(address: str) -> List[Execution]:
    return await Execution.query(owner=address)


@app.post("/executions/request")
async def request_execution(execution: Execution) -> Execution:
    pass


filters = [{
    "channel": aars.channel
}]

@app.event(filters=filters)
async def fishnet_event(event):
    print("fishnet_event", event)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
        async with session.get("https://official.aleph.cloud/api/v0/info/public.json") as resp:
            print('RESP', resp)
            resp.raise_for_status()
    return {
        "result": "Good"
    }
