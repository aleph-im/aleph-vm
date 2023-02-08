import logging
from typing import Optional

logger = logging.getLogger(__name__)

logger.debug("import aleph")
from aleph_message.models import PostMessage
from aleph_client.vm.cache import VmCache
from aleph_client.vm.app import AlephApp

logger.debug("import aars")
from aars import AARS, Record

logger.debug("import fastapi")
from fastapi import FastAPI

logger.debug("import fishnet-cod")
from fishnet_cod import Execution, run_execution

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
    if event.content.type in ["Execution"]:
        cls: Record = globals()[event.content.type]
        execution = await cls.from_post(event)
    else:  # amend
        execution = await Record.fetch(event.content.ref)
    assert isinstance(execution, Execution)
    return await run_execution(execution)
