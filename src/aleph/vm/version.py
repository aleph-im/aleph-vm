import logging
from subprocess import CalledProcessError, check_output

logger = logging.getLogger(__name__)


def get_version_from_git() -> str | None:
    try:
        return check_output(("git", "describe", "--tags")).strip().decode()
    except FileNotFoundError:
        logger.warning("git not found")
        return None
    except CalledProcessError:
        logger.warning("git description not available")
        return None


def get_version_from_apt() -> str | None:
    try:
        import apt

        return apt.Cache().get("aleph-vm").installed.version
    except (ImportError, AttributeError):
        logger.warning("apt version not available")
        return None


def get_version() -> str | None:
    return get_version_from_git() or get_version_from_apt()


# The version number is hardcoded in the following line when packaging the software
__version__ = get_version() or "version-unavailable"
