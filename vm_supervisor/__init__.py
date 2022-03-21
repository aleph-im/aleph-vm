from subprocess import check_output


def get_version_from_git() -> str:
    return check_output(("git", "describe", "--tags")).strip().decode()


# The version number is harcoded in the following line when packaging the software
__version__ = get_version_from_git()


from . import supervisor
