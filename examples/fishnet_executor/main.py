import json
import logging
from typing import Union

from aleph_message.models import PostMessage
from pydantic import BaseModel

logger = logging.getLogger(__name__)

logger.debug("import aleph_client")
from aleph_client.vm.cache import VmCache
from aleph_client.vm.app import AlephApp

logger.debug("import aars")
from aars import AARS

logger.debug("import fastapi")
from fastapi import FastAPI

logger.debug("import pandas")
import pandas as pd

logger.debug("import project modules")
from fishnet_cod import *

logger.debug("imports done")

http_app = FastAPI()
app = AlephApp(http_app=http_app)
cache = VmCache()
aars_client = AARS(channel="FISHNET_TEST")


@app.get("/")
async def index():
    return {"status": "ok"}


filters = [
    {
        "channel": aars_client.channel,
        "type": "POST",
        "post_type": ["Execution", "amend"],
    }
]


@app.event(filters=filters)
async def handle_execution(event: PostMessage) -> Optional[Execution]:
    async def set_failed(execution, reason):
        execution.status = ExecutionStatus.FAILED
        result = await Result.create(executionID=execution.id_hash, data=reason)
        execution.resultID = result.id_hash
        return await execution.upsert()

    if event.content.type in ["Execution"]:
        cls: Record = globals()[event.content.type]
        execution = await cls.from_post(event)
    else:  # amend
        execution = await Record.fetch(event.content.ref)
    assert isinstance(execution, Execution)
    if execution.status != ExecutionStatus.PENDING:
        return execution

    execution.status = ExecutionStatus.RUNNING
    await execution.upsert()

    try:
        try:
            algorithm = (await Algorithm.fetch(execution.algorithmID))[0]
        except IndexError:
            return await set_failed(
                execution, f"Algorithm {execution.algorithmID} not found"
            )

        try:
            exec(algorithm.code)
        except Exception as e:
            return await set_failed(execution, f"Failed to parse algorithm code: {e}")

        if "run" not in locals():
            return await set_failed(execution, "No run(df: DataFrame) function found")

        try:
            dataset = (await Dataset.fetch(execution.datasetID))[0]
        except IndexError:
            return await set_failed(
                execution, f"Dataset {execution.datasetID} not found"
            )

        timeseries = await Timeseries.fetch(dataset.timeseriesIDs)
        if len(timeseries) != len(dataset.timeseriesIDs):
            if len(timeseries) == 0:
                return await set_failed(
                    execution, f"Timeseries for dataset {dataset.id_hash} not found"
                )
            return await set_failed(
                execution,
                f"Timeseries incomplete: {len(timeseries)} out of {len(dataset.timeseriesIDs)} found",
            )

        try:
            # parse all timeseries as series and join them into a dataframe
            df = pd.concat(
                [
                    pd.Series(
                        [x[1] for x in ts.data],
                        index=[x[0] for x in ts.data],
                        name=ts.name,
                    )
                    for ts in timeseries
                ],
                axis=1,
            )
        except Exception as e:
            return await set_failed(execution, f"Failed to create dataframe: {e}")

        try:
            assert "run" in locals()
            result = locals()["run"](df)
        except Exception as e:
            return await set_failed(execution, f"Failed to run algorithm: {e}")

        result_message = await Result.create(
            executionID=execution.id_hash, data=str(result)
        )
        execution.status = ExecutionStatus.SUCCESS
        execution.resultID = result_message.id_hash
        await execution.upsert()
    except Exception as e:
        logger.error(f"Unexpected error occurred: {e}")
    finally:
        del locals()["run"]
        return execution
