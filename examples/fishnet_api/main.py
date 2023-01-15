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
from fastapi import FastAPI

logger.debug("import models")
from .model import *

logger.debug("imports done")

http_app = FastAPI()
app = AlephApp(http_app=http_app)
cache = VmCache()
aars = AARS(channel="FISHNET_TEST")


async def re_index():
    await Timeseries.regenerate_indices()
    await  UserInfo.regenerate_indices()
    await Dataset.regenerate_indices()
    await Algorithm.regenerate_indices()
    await Execution.regenerate_indices()
    await Permission.regenerate_indices()

    print("This will take few sec ...")
    await asyncio.sleep(3)


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


@app.get("/datasets")
async def datasets() -> List[Dataset]:
    return await Dataset.fetch_all()


@app.get("/user/{address}/datasets")
async def get_user_datasets(address: str) -> List[Dataset]:
    return await Dataset.query(owner=address)


@app.get("/algorithms")
async def get_algorithms() -> List[Algorithm]:
    return await Algorithm.fetch_all()


@app.get("/user/{address}/algorithms")
async def get_user_algorithms(address: str) -> List[Algorithm]:
    return await Algorithm.query(owner=address)


@app.get("/executions")
async def get_executions() -> List[Execution]:
    return await Execution.fetch_all()


@app.get("/user/{address}/executions")
async def get_user_executions(address: str) -> List[Execution]:
    return await Execution.query(owner=address)


@app.get("/allTimeseries")
async def post_timeseries():
    return await Timeseries.fetch_all()


@app.get("/allexecution")
async def post_timeseries():
    return await Execution.fetch_all()


@app.get("/allpermission")
async def post_timeseries():
    return await Permission.fetch_all()


@app.get("/executions/{execution_id}/possible_execution_count")
async def get_possible_execution_count(execution_id: str) -> int:
    """
    THIS IS AN OPTIONAL ENDPOINT. It is a nice challenge to implement this endpoint, as the code is not trivial and
    it might be still good to have this code in the future.

    This endpoint returns the number of times the execution can be executed.
    This is the maximum number of times
    the algorithm can be executed on the dataset, given the permissions of each timeseries.
    It can only be executed
    as many times as the least available timeseries can be executed.
    """

    execution = await Execution.fetch(execution_id)
    # challenged accepted but after moving the house


@app.put("/timeseries/upload")
async def upload_timeseries(timeseries: List[Timeseries]) -> List[Timeseries]:
    created_timeseries = await asyncio.gather(
        *[Timeseries.create(**dict(ts)) for ts in timeseries]
    )
    return [ts for ts in created_timeseries if not isinstance(ts, BaseException)]


@app.put("/datasets/upload")
async def upload_dataset(dataset: Dataset) -> Dataset:
    if dataset.ownsAllTimeseries:
        # check if _really_ owns all timeseries
        timeseries = await Timeseries.get(dataset.timeseriesIDs)
        dataset.ownsAllTimeseries = all([ts.owner == dataset.owner for ts in timeseries])
    return await dataset.upsert()


@app.put("/algorithms/upload")
async def upload_algorithm(algorithm: Algorithm) -> Algorithm:
    # TODO: Deploy program with the code and required packages

    return await algorithm.upsert()


@app.put("/executions/request")
async def request_execution(execution: Execution) -> Execution:
    """This is not working so risky to change the code"""
    dataset = (await Dataset.fetch([execution.datasetID]))[0]

    # allow execution if dataset owner == execution owner
    if dataset.owner == execution.owner and dataset.ownsAllTimeseries:
        execution.status = ExecutionStatus.PENDING
        return await execution.upsert()

    # check if execution owner has permission to read all timeseries
    requested_timeseries = await Timeseries.fetch(dataset.timeseriesIDs)
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


@app.put("/permissions/approve")
async def approve_permissions(permission_hashes: List[str]):
    """
    Approve a list of permissions by their item hashes.
    """

    # TODO: Check signature to match with owner's

    # TODO: grant permissions and update records
    await re_index()
    permission_record = await Permission.fetch(permission_hashes)
    for rec in permission_record:
        rec.status = PermissionStatus.GRANTED
        await rec.upsert()


@app.put("/permissions/deny")
async def deny_permissions(permission_hashes: List[str]):
    """
    Deny a list of permissions by their item hashes.
    """
    await re_index()
    permission_record = await Permission.fetch(permission_hashes)
    ts_ids = []

    for permission in permission_record:
        # deny permissions and update records
        permission.status = PermissionStatus.DENIED
        ts_ids.append(permission.timeseriesID)
        await permission.upsert()
    # get all executions that are waiting for this permission(status == PENDING) and update their status to DENIED
    dataset = await Dataset.fetch_all()
    ds_ids = []
    for data in dataset:
        if [i for i, j in zip(data.timeseriesIDs, ts_ids) if i == j]:
            ds_ids.append(data.id_hash)

    execution = await Execution.fetch_all()
    for rec in execution:
        if ds_ids and rec.datasetID in ds_ids and rec.status == ExecutionStatus.PENDING:
            rec.status = ExecutionStatus.DENIED
            await rec.upsert()


@app.put("/datasets/{dataset_id}/available/{available}")
async def set_dataset_available(dataset_id: str, available: bool):
    """
    Set a dataset to be available or not. This will also update the status of all executions that are waiting for
    permission on this dataset.
    """
    await re_index()
    # Check signature to match with owner's
    # This signature will be implemented by Mike
    resp = await Dataset.fetch(dataset_id)
    dataset = resp[0]
    # Check if dataset exists
    if resp:
        dataset.available = available
        await dataset.upsert()

        # Get all timeseries in the dataset and set them to available or not
        ts_list = await Timeseries.fetch(dataset.timeseriesIDs)
        ts_record = ts_list[0]
        if ts_record:
            ts_record.available = available
            await ts_record.upsert()
        else:
            print("No Timeseries data found")

        # Get all executions that are waiting for this dataset (status == PENDING) and update their status to DENIED
        execution = await Execution.fetch_all()
        for execution_rec in execution:
            if execution_rec.datasetID == dataset_id and execution_rec.status == ExecutionStatus.PENDING:
                execution_rec.status = ExecutionStatus.DENIED
                await execution_rec.upsert()
    else:
        return {"error": "dataset not found"}


filters = [{
    "channel": aars.channel,
    "type": "POST",
    "post_type": ["Execution", "Permission", "Dataset", "Timeseries", "Algorithm", "amend"],
}]


@app.event(filters=filters)
async def fishnet_event(event: PostMessage):
    print("fishnet_event", event)
    if event.content.type in ["Execution", "Permission", "Dataset", "Timeseries", "Algorithm"]:
        cls: Record = globals()[event.content.type]
        record = await cls.from_post(event)
    else:  # amend
        record = Record.fetch(event.content.ref)
    # update indexes
    [index.add_record(record) for index in record.get_indices()]
