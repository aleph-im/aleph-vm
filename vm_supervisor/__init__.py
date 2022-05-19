import logging
from subprocess import check_output, CalledProcessError
from typing import Optional

logger = logging.getLogger(__name__)


def get_version_from_git() -> Optional[str]:
    try:
        return check_output(("git", "describe", "--tags")).strip().decode()
    except FileNotFoundError:
        logger.warning("git not found")
        return None
    except CalledProcessError:
        logger.warning("git description not available")
        return None


def get_version_from_apt() -> Optional[str]:
    try:
        import apt
        return apt.Cache().get('aleph-vm').installed.version
    except ImportError:
        logger.warning("apt version not available")
        return None


def get_version() -> Optional[str]:
    return get_version_from_git() or get_version_from_apt()


# The version number is harcoded in the following line when packaging the software
__version__ = get_version() or "version-unavailable"


from . import supervisor
