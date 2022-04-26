import logging
from subprocess import check_output, CalledProcessError

logger = logging.getLogger(__name__)


def get_version_from_git() -> str:
    try:
        return check_output(("git", "describe", "--tags")).strip().decode()
    except FileNotFoundError:
        logger.warning("git not found")
        return "unknown-version"
    except CalledProcessError:
        logger.warning("git description not available")
        return "unavailable-version"


# The version number is harcoded in the following line when packaging the software
__version__ = get_version_from_git()


from . import supervisor
