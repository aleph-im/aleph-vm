import asyncio
import logging
import os
from os import listdir
from typing import Union

from aleph_message.models import PostMessage

logger = logging.getLogger(__name__)

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
    print("This will take few sec ...")
    await asyncio.gather(
        Timeseries.regenerate_indices(),
        UserInfo.regenerate_indices(),
        Dataset.regenerate_indices(),
        Algorithm.regenerate_indices(),
        Execution.regenerate_indices(),
        Permission.regenerate_indices(),
        asyncio.sleep(3)
    )


@app.on_event("startup")
async def startup():
    await re_index()


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
        timeseries = await Timeseries.fetch(dataset.timeseriesIDs)
        dataset.ownsAllTimeseries = all([ts.owner == dataset.owner for ts in timeseries])
    return await dataset.upsert()


@app.put("/algorithms/upload")
async def upload_algorithm(algorithm: Algorithm) -> Algorithm:
    # TODO: Deploy program with the code and required packages

    return await algorithm.upsert()


@app.put("/executions/request")
async def request_execution(execution: Execution) -> Tuple[Execution, Union[List[Permission], List[Timeseries]]]:
    """This is not working so risky to change the code"""
    dataset = (await Dataset.fetch([execution.datasetID]))[0]

    # allow execution if dataset owner == execution owner
    if dataset.owner == execution.owner and dataset.ownsAllTimeseries:
        execution.status = ExecutionStatus.PENDING
        return await execution.upsert(), []

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
    unavailable_timeseries = []
    for ts in requested_timeseries:
        if ts.owner == execution.owner:
            continue
        if not ts.available:
            execution.status = ExecutionStatus.DENIED
            unavailable_timeseries.append(ts)
            await execution.upsert()
        if execution.status == ExecutionStatus.DENIED:
            # continue to fetch all the unavailable timeseries
            continue
        if ts.id_hash not in permissions:
            # create permission request
            requests.append(Permission.create(
                timeseriesID=ts.id_hash,
                algorithmID=execution.algorithmID,
                owner=ts.owner,
                reader=execution.owner,
                status=PermissionStatus.REQUESTED,
                executionCount=0,
                maxExecutionCount=1,
            ))
        else:
            # check if permission is valid
            permission = permissions[ts.id_hash]
            needs_update = False  # helper variable to avoid unnecessary updates
            if permission.status == PermissionStatus.DENIED:
                permission.status = PermissionStatus.REQUESTED
                needs_update = True
            if permission.maxExecutionCount <= permission.executionCount:
                permission.maxExecutionCount = permission.executionCount + 1
                permission.status = PermissionStatus.REQUESTED  # re-request permission
                needs_update = True
            if needs_update:
                requests.append(permission.upsert())
    if unavailable_timeseries:
        return execution, unavailable_timeseries
    if requests:
        new_permission_requests = await asyncio.gather(*requests)
        execution.status = ExecutionStatus.REQUESTED
    else:
        new_permission_requests = []
        execution.status = ExecutionStatus.PENDING

    return await execution.upsert(), new_permission_requests


@app.post("/datapost")
async def datapost(permission: Permission):
    await permission.upsert()


@app.put("/permissions/approve")
async def approve_permissions(permission_hashes: List[str]):
    """
    Approve a list of permissions by their item hashes.
    """
    ts_ids = []
    requests = []
    # TODO: Check signature to match with owner's

    permission_record = await Permission.fetch(permission_hashes)
    if permission_record:
        for rec in permission_record:
            rec.status = PermissionStatus.GRANTED
            ts_ids.append(rec.timeseriesID)
            requests.append(rec.upsert())

        # TODO: check if execution can be executed now
        ds_ids = []
        dataset = await Dataset.fetch(ts_ids)
        if dataset:
            for data in dataset:
                if data.id_hash in ds_ids:
                    ds_ids.append(data.id_hash)

            executions = await Execution.fetch(ds_ids)
            if executions:
                for execution in executions:
                    if ds_ids and execution.datasetID in ds_ids:
                        execution.status = ExecutionStatus.PENDING
                        requests.append(rec.upsert())
                await asyncio.gather(requests)
                return {"Success": "Permissions Approved "}
            else:
                return {"Execution": "No Execution found "}
        else:
            return {"Dataset": "No Dataset found"}
    else:
        return {"Permission": "No Permission Found with this Hashes"}


@app.put("/permissions/deny")
async def deny_permissions(permission_hashes: List[str]):
    """
    Deny a list of permissions by their item hashes.
    """
    permission_record = await Permission.fetch(permission_hashes)
    if permission_record:
        ts_ids = []
        requests = []
        for permission in permission_record:
            # deny permissions and update records
            permission.status = PermissionStatus.DENIED
            ts_ids.append(permission.timeseriesID)
            requests.append(permission.upsert())
        dataset = await Dataset.fetch(ts_ids)
        ds_ids = []
        if dataset:
            for data in dataset:
                ds_ids.append(data.id_hash)
            # Avoided fetching all executions
            execution = await Execution.fetch(ds_ids)
            if execution:
                for rec in execution:
                    # get all executions that are waiting for this permission(status == PENDING) and update their status to DENIED
                    if rec.datasetID in ds_ids and rec.status == ExecutionStatus.PENDING:
                        rec.status = ExecutionStatus.DENIED
                        requests.append(rec.upsert())
                # parellel processed
                await asyncio.gather(requests)
                return {"Success": "Denied all Permissions"}
            else:
                return {"Execution": "No Execution found "}
        else:
            return {"Timeseries": "No Timeseries found"}
    else:
        return {"Permission": "No Permission found with this Hashes"}


@app.put("/datasets/{dataset_id}/available/{available}")
async def set_dataset_available(dataset_id: str, available: bool):
    """
    Set a dataset to be available or not. This will also update the status of all executions that are waiting for
    permission on this dataset.
    """
    # Check signature to match with owner's
    # This signature will be implemented by Mike
    requests = []
    resp = await Dataset.fetch(dataset_id)
    # Handled the case when the dataset is not found
    if resp:
        dataset = resp[0]
        dataset.available = available
        requests.append(dataset.upsert())

        # Get all timeseries in the dataset and set them to available or not
        ts_list = await Timeseries.fetch(dataset.timeseriesIDs)
        if ts_list:
            ts_record = ts_list[0]
            # check if the timeseries is updated or not and only update the timeseries when it is needed
            if ts_record.available != available:
                ts_record.available = available
                requests.append(ts_record.upsert())
            else:
                return {"error": "Record is already Updated"}

            # Get all executions that are waiting for this dataset (status == PENDING) and update their status to DENIED
            execution = await Execution.fetch(dataset_id)
            if execution:
                for execution_rec in execution:
                    if execution_rec.status == ExecutionStatus.PENDING:
                        execution_rec.status = ExecutionStatus.DENIED
                        requests.append(execution_rec.upsert())

                # executed all requests in parallel
                await asyncio.gather(requests)
                return {"Success": "Dataset availability has been set successfully "}
            else:
                return {"Execution": "No Execution found "}
        else:
            return {"Timeseries": "No Timeseries found"}
    else:
        return {"Dataset": "No Dataset found"}


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
