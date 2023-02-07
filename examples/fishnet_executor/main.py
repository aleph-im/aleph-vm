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
    return {
        "status": "ok"
    }


filters = [{
    "channel": aars_client.channel,
    "type": "POST",
    "post_type": ["Execution", "amend"],
}]


class FishnetContent(BaseModel):
    type: str
    ref: str


class FishnetEvent(BaseModel):
    content: FishnetContent


@app.event(filters=filters)
async def handle_execution(event: Union[PostMessage, FishnetEvent]) -> Optional[Execution]:
    print("fishnet_event", event)
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
            logger.error(f"Algorithm {execution.algorithmID} not found")
            return
        finally:
            await set_failed(execution)

        try:
            exec(algorithm.code)
        except Exception as e:
            logger.error(f"Failed to parse algorithm code: {e}")
            return
        finally:
            await set_failed(execution)

        if "run" not in locals():
            logger.error("No run(df: DataFrame) function found")
            await set_failed(execution)
            return

        try:
            dataset = (await Dataset.fetch(execution.datasetID))[0]
        except IndexError:
            logger.error(f"Dataset {execution.datasetID} not found")
            return
        finally:
            await set_failed(execution)

        timeseries = await Timeseries.fetch(dataset.timeseriesIDs)
        if len(timeseries) != len(dataset.timeseriesIDs):
            if len(timeseries) == 0:
                logger.error(f"Timeseries for dataset {dataset.id_hash} not found")
                await set_failed(execution)
                return execution
            logger.warning(f"Timeseries incomplete: {len(timeseries)} out of {len(dataset.timeseriesIDs)} found")

        try:
            df = pd.concat([pd.DataFrame(ts.data, columns=["time", ts.name]) for ts in timeseries], axis=1)
        except Exception as e:
            logger.error(f"Failed to create dataframe: {e}")
            return
        finally:
            await set_failed(execution)

        try:
            assert "run" in locals()
            result = locals()["run"](df)
        except Exception as e:
            logger.error(f"Failed to run algorithm: {e}")
            await set_failed(execution)
            return

        result_message = await Result.create(executionID=execution.id_hash, data=json.dumps(result))
        execution.status = ExecutionStatus.SUCCESS
        execution.resultID = result_message.id_hash
        await execution.upsert()
    except Exception as e:
        logger.error(f"Unexpected error occurred: {e}")
    finally:
        del locals()["run"]
        return execution


async def set_failed(execution):
    execution.status = ExecutionStatus.FAILED
    await execution.upsert()
