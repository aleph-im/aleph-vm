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


# TODO: Include OpenAPI from FastAPI and document endpoints

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


@app.put("/timeseries/upload")
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


@app.put("/datasets/upload")
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


@app.put("/algorithms/upload")
async def upload_algorithm(algorithm: Algorithm) -> Algorithm:
    # TODO: Deploy program with the code and required packages
    return await algorithm.upsert()


@app.get("/executions")
async def get_executions() -> List[Execution]:
    return await Execution.fetch_all()


@app.get("/user/{address}/executions")
async def get_user_executions(address: str) -> List[Execution]:
    return await Execution.query(owner=address)


@app.put("/executions/request")
async def request_execution(execution: Execution) -> Execution:
    dataset = (await Dataset.get([execution.datasetID]))[0]
    # allow execution if dataset owner == execution owner
    if dataset.owner == execution.owner and dataset.ownsAllTimeseries:
        execution.status = ExecutionStatus.PENDING
        return await execution.upsert()

    # check if execution owner has permission to read all timeseries
    requested_timeseries = await Timeseries.get(dataset.timeseriesIDs)
    permissions = {
        permission.timeseriesID: permission
        for permission in await Permission.query(
            timeseriesID=dataset.timeseriesIDs,
            reader=execution.owner
        )
    }
    requests = []
    for ts in requested_timeseries:
        if ts.owner == execution.owner:
            continue
        if not ts.available:
            execution.status = ExecutionStatus.DENIED
            return await execution.upsert()  # TODO: return unavailable timeseries too
        if ts.item_hash not in permissions:
            requests.append(Permission.create(
                timeseriesID=ts.item_hash,
                algorithmID=execution.algorithmID,
                owner=ts.owner,
                reader=execution.owner,
                status=PermissionStatus.REQUESTED,
                executionCount=0,
                maxExecutionCount=1,
            ))
        else:
            # check if permission is valid
            permission = permissions[ts.item_hash]
            needs_update = False
            if permission.status == PermissionStatus.DENIED:
                permission.status = PermissionStatus.REQUESTED
                needs_update = True
            if permission.maxExecutionCount <= permission.executionCount:
                permission.maxExecutionCount = permission.executionCount + 1
                needs_update = True
            if needs_update:
                requests.append(permission.upsert())
    if len(requests) > 0:
        new_permission_requests = await asyncio.gather(*requests)
    execution.status = ExecutionStatus.REQUESTED

    return await execution.upsert()  # TODO: return new permission requests


@app.get("/executions/{execution_id}/possible_execution_count")
async def get_possible_execution_count(execution_id: str) -> int:
    """
    THIS IS AN OPTIONAL ENDPOINT. It is a nice challenge to implement this endpoint, as the code is not trivial and
    it might be still good to have this code in the future.

    This endpoint returns the number of times the execution can be executed. This is the maximum number of times
    the algorithm can be executed on the dataset, given the permissions of each timeseries. It can only be executed
    as many times as the least available timeseries can be executed.
    """
    pass


@app.put("/permissions/approve")
async def approve_permissions(permission_hashes: List[str]):
    """
    Approve a list of permissions by their item hashes.
    """
    # TODO: Check signature to match with owner's
    permissions = Permission.get(permission_hashes)
    # TODO: grant permissions and update records


@app.put("/permissions/deny")
async def deny_permissions(permission_hashes: List[str]):
    """
    Deny a list of permissions by their item hashes.
    """
    permissions = Permission.get(permission_hashes)
    # TODO: deny permissions and update records
    # TODO: get all executions that are waiting for this permission (status == PENDING) and update their status to DENIED


@app.put("/datasets/{dataset_id}/available/{available}")
async def set_dataset_available(dataset_id: str, available: bool):
    """
    Set a dataset to be available or not. This will also update the status of all executions that are waiting for
    permission on this dataset.
    """
    # TODO: Check signature to match with owner's
    resp = (await Dataset.get(dataset_id))
    # TODO: Check if dataset exists
    dataset = resp[0]
    # TODO: Check if action is necessary
    dataset.available = available
    await dataset.upsert()
    # TODO: Get all timeseries in the dataset and set them to available or not
    # TODO: Get all executions that are waiting for this dataset (status == PENDING) and update their status to DENIED


filters = [{
    "channel": aars.channel,
    "type": "POST",
    "post_type": "Execution"
}]

# TODO: Add listener for execution status changes (maybe extra VM?)
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
