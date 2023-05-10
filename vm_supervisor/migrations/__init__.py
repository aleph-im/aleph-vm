import logging
from pathlib import Path

import alembic.command
import alembic.config

from ..conf import make_db_url
from ..utils import run_in_directory


def run_db_migrations():
    project_dir = Path(__file__).parent

    db_url = make_db_url()
    alembic_cfg = alembic.config.Config("alembic.ini")
    alembic_cfg.attributes["configure_logger"] = False
    logging.getLogger("alembic").setLevel(logging.CRITICAL)

    with run_in_directory(project_dir):
        alembic.command.upgrade(alembic_cfg, "head", tag=db_url)
