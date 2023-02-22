import asyncio
import logging
import os
from os import listdir, getenv

from aleph_message.models import PostMessage

logger = logging.getLogger(__name__)

logger.debug("import aleph_client")
from aleph_client.vm.cache import VmCache, TestVmCache
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

if getenv("TEST_CACHE") is not None and getenv("TEST_CACHE").lower() == "true":
    cache = TestVmCache()
else:
    cache = VmCache()
app = AlephApp(http_app=http_app)
aars = AARS(channel="FISHNET_TEST", cache=cache)


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
        "endpoints": [
            "/timeseries/upload",
            "/datasets",
            "/user/{address}/datasets",
            "/datasets/upload",
            "/algorithms",
            "/user/{address}/algorithms",
            "/algorithms/upload",
            "/executions",
            "/user/{address}/executions",
        ],
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
async def datasets(view_as: Optional[str], by: Optional[str]) -> str:
    """
    Get all datasets.

    :param view_as: address of the user to view the datasets as and give additional permission information
    :param by: address of the dataset owner to filter by
    """
    # TODO:
    # - for the Owner (by) parameter:
    #     - fetch all datasets for the owner
    ds_by_owner = await Dataset.where_eq(owner=by)
    ts_by_owner = ds_by_owner[0].timeseriesIDs
    # - for the Requestor (view_as) parameter:
    #     - fetch all timeseries for each dataset,

    timeseries_records = await Timeseries.fetch(ts_by_owner)
    timeseries_ids = timeseries_records[0].id_hash
    #   - get all permissions for each timeseries & given requestor
    permission_status = []
    permission_records = await Permission.where_eq(timeseriesID=timeseries_ids, requestor=view_as)
    for rec in permission_records:
        permission_status.append(rec.status)
    #   - respond with permission for dataset as approved, if all permissions are approved
    if all(rec == PermissionStatus.GRANTED for rec in permission_status):
        return "Dataset Available"
    #     - respond with pending if at least one is still pending
    elif PermissionStatus.REQUESTED in permission_status:
        return "Dataset Requested"
    #     - respond with denied if at lest one is denied
    elif PermissionStatus.DENIED in permission_status:
        return "Dataset Denied"


# This is not necessary, as it will be replaced by GET /datasets?by={address}
#@app.get("/user/{address}/datasets")
#async def get_user_datasets(address: str) -> List[Dataset]:
#    return await Dataset.save(owner=address)


@app.get("/algorithms")
async def get_algorithms() -> List[Algorithm]:
    return await Algorithm.fetch_all()


@app.get("/user/{address}/algorithms")
async def get_user_algorithms(address: str) -> List[Algorithm]:
    return await Algorithm.where_eq(owner=address)


@app.get("/executions")
async def get_executions() -> List[Execution]:
    return await Execution.fetch_all()


@app.get("/executions/{dataset_ID}")
async def get_executions_by_dataset(dataset_ID: str) -> List[Execution]:
    return await Execution.where_eq(datasetID=dataset_ID)


@app.get("/user/{address}/executions")
async def get_user_executions(address: str) -> List[Execution]:
    return await Execution.where_eq(owner=address)


@app.get("/user/{address}/results")
async def get_user_results(address: str) -> List[Result]:
    return await Result.where_eq(owner=address)


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
    old_time_series = (
        {ts.id_hash: ts for ts in await Timeseries.fetch(ids_to_fetch)}
        if ids_to_fetch
        else {}
    )
    for ts in req.timeseries:
        if old_time_series.get(ts.id_hash) is None:
            requests.append(Timeseries(**dict(ts)).save())
            continue
        old_ts: Timeseries = old_time_series[ts.id_hash]
        if ts.owner != old_ts.owner:
            raise HTTPException(status_code=403, detail="Cannot overwrite timeseries that is not owned by you")
        old_ts.name = ts.name
        old_ts.data = ts.data
        old_ts.desc = ts.desc
        requests.append(old_ts.save())
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
        dataset.ownsAllTimeseries = all(
            [ts.owner == dataset.owner for ts in timeseries]
        )
    if dataset.id_hash is not None:
        # update existing dataset
        resp = await Dataset.fetch(dataset.id_hash)
        old_dataset = resp[0] if resp else None
        if old_dataset is not None:
            if old_dataset.owner != dataset.owner:
                raise HTTPException(status_code=403, detail="Cannot overwrite dataset that is not owned by you")
            old_dataset.name = dataset.name
            old_dataset.desc = dataset.desc
            old_dataset.timeseriesIDs = dataset.timeseriesIDs
            old_dataset.ownsAllTimeseries = dataset.ownsAllTimeseries
            return await old_dataset.save()
    return await Dataset(**dataset.dict()).save()


@app.put("/algorithms/upload")
async def upload_algorithm(algorithm: UploadAlgorithmRequest) -> Algorithm:
    """
    Upload an algorithm.
    If an `id_hash` is provided, it will update the algorithm with that id.
    """
    if algorithm.id_hash is not None:
        # update existing algorithm
        resp = await Algorithm.fetch(algorithm.id_hash)
        old_algorithm = resp[0] if resp else None
        if old_algorithm is not None:
            if old_algorithm.owner != algorithm.owner:
                raise HTTPException(status_code=403, detail="Cannot overwrite algorithm that is not owned by you")
            old_algorithm.name = algorithm.name
            old_algorithm.desc = algorithm.desc
            old_algorithm.code = algorithm.code
            return await old_algorithm.save()
    return await Algorithm(**algorithm.dict()).save()


@app.post("/executions/request")
async def request_execution(
        execution: RequestExecutionRequest,
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
        return RequestExecutionResponse(execution=await Execution(**execution.dict()).save())

    # check if execution owner has permission to read all timeseries
    requested_timeseries = await Timeseries.fetch(dataset.timeseriesIDs)
    permissions = {
        permission.timeseriesID: permission
        for permission in await Permission.where_eq(timeseriesID=dataset.timeseriesIDs, requestor=execution.owner)
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
            requests.append(
                Permission(
                    timeseriesID=ts.id_hash,
                    algorithmID=execution.algorithmID,
                    owner=ts.owner,
                    requestor=execution.owner,
                    status=PermissionStatus.REQUESTED,
                    executionCount=0,
                    maxExecutionCount=1,
                ).save()
            )
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
                requests.append(permission.save())
    if unavailable_timeseries:
        execution.status = ExecutionStatus.DENIED
        return RequestExecutionResponse(
            execution=await Execution(**execution.dict()).save(),
            unavailableTimeseries=unavailable_timeseries,
        )
    if requests:
        new_permission_requests = await asyncio.gather(*requests)
        execution.status = ExecutionStatus.REQUESTED
        return RequestExecutionResponse(
            execution=await Execution(**execution.dict()).save(),
            permissionRequests=new_permission_requests,
        )
    else:
        execution.status = ExecutionStatus.PENDING
        return RequestExecutionResponse(
            execution=await Execution(**execution.dict()).save()
        )


@app.put("/permissions/approve")
async def approve_permissions(permission_hashes: List[str]) -> List[Permission]:
    """
    Approve permission.
    This EndPoint will approve a list of permissions by their item hashes
    If an `id_hashes` is provided, it will change all the Permission status
    to Granted.
    """

    ts_ids = []
    requests = []
    # TODO: Check signature to match with owner's

    permission_records = await Permission.fetch(permission_hashes)
    if not permission_records:
        raise HTTPException(status_code=404, detail="No Permission Found with this Hashes")

    for rec in permission_records:
        rec.status = PermissionStatus.GRANTED
        ts_ids.append(rec.timeseriesID)
        requests.append(rec.save())

    # TODO: check if execution can be executed now
    ds_ids = []
    dataset_records = await Dataset.where_eq(timeseriesIDs=ts_ids)
    if not dataset_records:
        raise HTTPException(status_code=404, detail="No Dataset found")
    for rec in dataset_records:
        if rec.id_hash in ds_ids:
            ds_ids.append(rec.id_hash)

    executions_records = await Execution.where_eq(datasetID=ds_ids)
    for rec in executions_records:
        if ds_ids and rec.datasetID in ds_ids:
            rec.status = ExecutionStatus.PENDING
            requests.append(rec.save())
    await asyncio.gather(*requests)
    return permission_records


@app.put("/permissions/deny")
async def deny_permissions(permission_hashes: List[str]) -> List[Permission]:
    """
    Deny permission.
    This EndPoint will deny a list of permissions by their item hashes
    If an `id_hashes` is provided, it will change all the Permission status
    to Denied.
    """
    permission_records = await Permission.fetch(permission_hashes)
    if not permission_records:
        raise HTTPException(status_code=404, detail="No Permission found with this Hashes")

    ts_ids = []
    requests = []
    for rec in permission_records:
        # deny permissions and update records
        rec.status = PermissionStatus.DENIED
        ts_ids.append(rec.timeseriesID)
        requests.append(rec.save())
    dataset_records = await Dataset.where_eq(timeseriesIDs=ts_ids)
    ds_ids = []
    if not dataset_records:
        raise HTTPException(status_code=424, detail="No Timeseries found")
    for rec in dataset_records:
        ds_ids.append(rec.id_hash)
    # Avoided fetching all executions
    executions_records = await Execution.where_eq(datasetID=ds_ids)
    for rec in executions_records:
        # get all executions that are waiting for this permission(status == PENDING) and update their status to DENIED
        if (rec.datasetID in ds_ids and rec.status == ExecutionStatus.PENDING):
            rec.status = ExecutionStatus.DENIED
            requests.append(rec.save())
    # parellel processed
    await asyncio.gather(*requests)
    return permission_records


@app.put("/datasets/{dataset_id}/available/{available}")
async def set_dataset_available(dataset_id: str, available: bool) -> List[Dataset]:
    """
    Set a dataset to be available or not. This will also update the status of all
    executions that are waiting for permission on this dataset.
    """
    # Check signature to match with owner's
    # This signature will be implemented by Mike
    requests = []
    resp = await Dataset.fetch(dataset_id)
    # Handled the case when the dataset is not found
    if not resp:
        raise HTTPException(status_code=404, detail="No Dataset found")
    dataset = resp[0]
    dataset.available = available

    requests.append(dataset.save())

    # Get all timeseries in the dataset and set them to available or not
    ts_list = await Timeseries.fetch(dataset.timeseriesIDs)
    if not ts_list:
        raise HTTPException(status_code=424, detail="No Timeseries found")

    # check if the timeseries is updated or not and only update the timeseries when it is needed
    for rec in ts_list:
        if rec.available != available:
            rec.available = available
            requests.append(rec.save())
    # Get all executions that are waiting for this dataset (status == PENDING) and update their status to DENIED
    executions_records = await Execution.fetch(dataset_id)
    for rec in executions_records:
        if rec.status == ExecutionStatus.PENDING:
            rec.status = ExecutionStatus.DENIED
            requests.append(rec.save())

    # executed all requests in parallel
    await asyncio.gather(*requests)
    return resp


filters = [
    {
        "channel": aars.channel,
        "type": "POST",
        "post_type": [
            "Execution",
            "Permission",
            "Dataset",
            "Timeseries",
            "Algorithm",
            "amend",
        ],
    }
]


@app.event(filters=filters)
async def fishnet_event(event: PostMessage):
    print("fishnet_event", event)
    if event.content.type in [
        "Execution",
        "Permission",
        "Dataset",
        "Timeseries",
        "Algorithm",
    ]:
        cls: Record = globals()[event.content.type]
        record = await cls.from_post(event)
    else:  # amend
        record = Record.fetch(event.content.ref)
    # update indexes
    [index.add_record(record) for index in record.get_indices()]
