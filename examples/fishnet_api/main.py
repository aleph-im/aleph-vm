import asyncio
import logging
import os
from os import listdir

from aleph_message.models import PostMessage

logger = logging.getLogger(__name__)

logger.debug("import aleph_client")
from aleph_client.vm.cache import VmCache
from aleph_client.vm.app import AlephApp

logger.debug("import aars")
from aars import AARS

logger.debug("import fastapi")
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

logger.debug("import project modules")
from fishnet_cod import *
from .requests import *

logger.debug("imports done")

http_app = FastAPI()

origins = ["*"]

http_app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app = AlephApp(http_app=http_app)
cache = VmCache()
aars = AARS(channel="FISHNET_TEST")


async def re_index():
    logger.info("API re-indexing")
    await asyncio.wait_for(AARS.sync_indices(), timeout=None)
    logger.info("API re-indexing done")


@http_app.on_event("startup")
async def startup():
    await re_index()


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


@app.get("/indices")
async def index():
    ts = [list(index.hashmap.items()) for index in Timeseries.get_indices()]
    ui = [list(index.hashmap.items()) for index in UserInfo.get_indices()]
    ds = [list(index.hashmap.items()) for index in Dataset.get_indices()]
    al = [list(index.hashmap.items()) for index in Algorithm.get_indices()]
    ex = [list(index.hashmap.items()) for index in Execution.get_indices()]
    pe = [list(index.hashmap.items()) for index in Permission.get_indices()]
    return ts, ui, ds, al, ex, pe


@app.get("/indices/reindex")
async def index():
    await re_index()


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


@app.get("/executions/{dataset_ID}")
async def get_executions_by_dataset(dataset_ID: str) -> List[Execution]:
    return await Execution.query(datasetID=dataset_ID)


@app.get("/user/{address}/executions")
async def get_user_executions(address: str) -> List[Execution]:
    return await Execution.query(owner=address)


@app.get("/user/{address}/results")
async def get_user_results(address: str) -> List[Result]:
    return await Result.query(owner=address)


@app.get("/executions/{execution_id}/possible_execution_count")
async def get_possible_execution_count(execution_id: str) -> int:
    """
    THIS IS AN OPTIONAL ENDPOINT. It is a nice challenge to implement this endpoint, as the code is not trivial, and
    it might be still good to have this code in the future.

    This endpoint returns the number of times the execution can be executed.
    This is the maximum number of times
    the algorithm can be executed on the dataset, given the permissions of each timeseries.
    It can only be executed
    as many times as the least available timeseries can be executed.
    """

    execution = await Execution.fetch(execution_id)
    # challenged accepted but after moving the house
    return -1


@app.put("/timeseries/upload")
async def upload_timeseries(req: UploadTimeseriesRequest) -> List[Timeseries]:
    """
    Upload a list of timeseries. If the passed timeseries has an `id_hash` and it already exists,
    it will be overwritten. If the timeseries does not exist, it will be created.
    A list of the created/updated timeseries is returned. If the list is shorter than the passed list, then
    it might be that a passed timeseries contained illegal data.
    """
    ids_to_fetch = [ts.id_hash for ts in req.timeseries if ts.id_hash is not None]
    requests = []
    old_time_series = {ts.id_hash: ts for ts in await Timeseries.fetch(ids_to_fetch)} if ids_to_fetch else {}
    for ts in req.timeseries:
        if old_time_series.get(ts.id_hash) is None:
            requests.append(Timeseries.create(**dict(ts)))
            continue
        old_ts: Timeseries = old_time_series[ts.id_hash]
        if ts.owner != old_ts.owner:
            raise Exception("Cannot overwrite timeseries that is not owned by you")
        old_ts.name = ts.name
        old_ts.data = ts.data
        old_ts.desc = ts.desc
        requests.append(old_ts.upsert())
    upserted_timeseries = await asyncio.gather(*requests)
    return [ts for ts in upserted_timeseries if not isinstance(ts, BaseException)]


@app.put("/datasets/upload")
async def upload_dataset(dataset: UploadDatasetRequest) -> Dataset:
    """
    Upload a dataset.
    If an `id_hash` is provided, it will update the dataset with that id.
    """
    if dataset.ownsAllTimeseries:
        # check if _really_ owns all timeseries
        timeseries = await Timeseries.fetch(dataset.timeseriesIDs)
        dataset.ownsAllTimeseries = all([ts.owner == dataset.owner for ts in timeseries])
    if dataset.id_hash is not None:
        # update existing dataset
        resp = (await Dataset.fetch(dataset.id_hash))
        old_dataset = resp[0] if resp else None
        if old_dataset is not None:
            if old_dataset.owner != dataset.owner:
                raise Exception("Cannot overwrite dataset that is not owned by you")
            old_dataset.name = dataset.name
            old_dataset.desc = dataset.desc
            old_dataset.timeseriesIDs = dataset.timeseriesIDs
            old_dataset.ownsAllTimeseries = dataset.ownsAllTimeseries
            return await old_dataset.upsert()
    return await Dataset.create(**dataset.dict())


@app.put("/algorithms/upload")
async def upload_algorithm(algorithm: UploadAlgorithmRequest) -> Algorithm:
    """
    Upload an algorithm.
    If an `id_hash` is provided, it will update the algorithm with that id.
    """
    if algorithm.id_hash is not None:
        # update existing algorithm
        resp = (await Algorithm.fetch(algorithm.id_hash))
        old_algorithm = resp[0] if resp else None
        if old_algorithm is not None:
            if old_algorithm.owner != algorithm.owner:
                raise Exception("Cannot overwrite algorithm that is not owned by you")
            old_algorithm.name = algorithm.name
            old_algorithm.desc = algorithm.desc
            old_algorithm.code = algorithm.code
            return await old_algorithm.upsert()
    return await Algorithm.create(**algorithm.dict())


@app.post("/executions/request")
async def request_execution(
        execution: RequestExecutionRequest
) -> RequestExecutionResponse:
    """
    This endpoint is used to request an execution.
    If the user needs some permissions, the timeseries for which the user needs permissions are returned and
    the execution status is set to "requested". The needed permissions are also being requested. As soon as the
    permissions are granted, the execution is automatically executed.
    If some timeseries are not available, the execution is "denied" and the execution as well as the
    unavailable timeseries are returned.
    If the user has all permissions, the execution is started and the execution is returned.
    """
    dataset = (await Dataset.fetch([execution.datasetID]))[0]

    # allow execution if dataset owner == execution owner
    if dataset.owner == execution.owner and dataset.ownsAllTimeseries:
        execution.status = ExecutionStatus.PENDING
        return RequestExecutionResponse(
            execution=await Execution.create(**execution.dict())
        )

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
            unavailable_timeseries.append(ts)
        if requested_timeseries:
            # continue to fetch all the unavailable timeseries for the denied response
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
        execution.status = ExecutionStatus.DENIED
        return RequestExecutionResponse(
            execution=await Execution.create(**execution.dict()),
            unavailableTimeseries=unavailable_timeseries
        )
    if requests:
        new_permission_requests = await asyncio.gather(*requests)
        execution.status = ExecutionStatus.REQUESTED
        return RequestExecutionResponse(
            execution=await Execution.create(**execution.dict()),
            permissionRequests=new_permission_requests
        )
    else:
        execution.status = ExecutionStatus.PENDING
        return RequestExecutionResponse(
            execution=await Execution.create(**execution.dict())
        )


@app.put("/permissions/approve")
async def approve_permissions(permission_hashes: List[str]) -> FishnetResponseDataset:
    """
    Approve permission.
    This EndPoint will approve a list of permissions by their item hashes
    If an `id_hashes` is provided, it will change all the Permission status
    to Granted.
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
        dataset = await Dataset.query(timeseriesIDs=ts_ids)
        if dataset:
            for data in dataset:
                if data.id_hash in ds_ids:
                    ds_ids.append(data.id_hash)

            executions = await Execution.query(datasetID=ds_ids)
            if executions:
                for execution in executions:
                    if ds_ids and execution.datasetID in ds_ids:
                        execution.status = ExecutionStatus.PENDING
                        requests.append(execution.upsert())
                await asyncio.gather(*requests)
                return FishnetResponseDataset(success=True, message=permission_record)
            else:
                raise HTTPException(status_code=404, detail="No Execution found ")
        else:
            raise HTTPException(status_code=404, detail="No Dataset found")
    else:
        raise HTTPException(status_code=404, detail="No Permission Found with this Hashes")


@app.put("/permissions/deny")
async def deny_permissions(permission_hashes: List[str]) -> FishnetResponseDataset:
    """
    Deny permission.
    This EndPoint will approve a list of permissions by their item hashes
    If an `id_hashes` is provided, it will change all the Permission status
    to DENIED.
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
        dataset = await Dataset.query(timeseriesIDs=ts_ids)
        ds_ids = []
        if dataset:
            for data in dataset:
                ds_ids.append(data.id_hash)
            # Avoided fetching all executions
            execution = await Execution.query(datasetID=ds_ids)
            if execution:
                for rec in execution:
                    # get all executions that are waiting for this permission(status == PENDING) and update their status to DENIED
                    if rec.datasetID in ds_ids and rec.status == ExecutionStatus.PENDING:
                        rec.status = ExecutionStatus.DENIED
                        requests.append(rec.upsert())
                # parellel processed
                await asyncio.gather(*requests)
                return FishnetResponseDataset(success=True, message=permission_record)
            else:
                raise HTTPException(status_code=404, detail="No Execution found")
        else:
            raise HTTPException(status_code=404, detail="No Timeseries found")
    else:
        raise HTTPException(status_code=404, detail="No Permission found with this Hashes")


@app.put("/datasets/{dataset_id}/available/{available}")
async def set_dataset_available(dataset_id: str, available: bool) -> FishnetResponseDataset:
    """
    Set a dataset to be available or not. This will also update the status of all
    executions that are waiting for permission on this dataset.
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

            # Get all executions that are waiting for this dataset (status == PENDING) and update their status to DENIED
            # execution = await Execution.fetch(dataset_id)
            # print(execution, "This are the executions")
            # if execution:
            #     for execution_rec in execution:
            #         if execution_rec.status == ExecutionStatus.PENDING:
            #             execution_rec.status = ExecutionStatus.DENIED
            #             requests.append(execution_rec.upsert())

            # executed all requests in parallel
            await asyncio.gather(*requests)
            return FishnetResponseDataset(success=True, message=resp)
            # else:
            #     return {"Execution": "No Execution found "}
        else:
            raise HTTPException(status_code=404, detail="No Timeseries found")
    else:
        raise HTTPException(status_code=404, detail="No Dataset found")


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
