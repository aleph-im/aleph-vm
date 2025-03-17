import asyncio
import logging
import shutil
import sys
import time

logger = logging.getLogger(__name__)


async def get_du_size(path: str, *, apparent: bool = False) -> int:
    """Runs 'du' to get total size of a folder.

    If `apparent` is True, includes sparse files and unallocated blocks,
    showing the size as seen by applications rather than actual disk usage.
    """
    cmd = ["du", "--bytes", "--summarize", "--one-file-system", "--exclude=lost+found"]
    if apparent:
        cmd.append("--apparent-size")
    cmd.append(path)

    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        error_message = stderr.decode().strip().split("\n")[-1] if stderr else "Unknown error"
        logging.error(f"Error running {' '.join(cmd)}: {error_message}")
        return 0

    size_unparsed = stdout.split()[0]
    return int(size_unparsed)


async def calculate_available_disk_space(path: str) -> int:
    """Calculate available disk space based on actual and apparent disk usage as bytes."""
    total, used, free = shutil.disk_usage(path)
    real_usage, apparent_usage = await asyncio.gather(get_du_size(path), get_du_size(path, apparent=True))
    return free - (real_usage + apparent_usage)


# cache and lock
_CACHE_TTL = 20
_DISK_SPACE_CACHE: dict = {}
_DISK_SPACE_LOCK = asyncio.Lock()


async def get_available_disk_space_cached(path: str) -> int:
    """Calculates available disk space considering sparse files with caching and async lock as bytes."""

    async with _DISK_SPACE_LOCK:
        cached_entry = _DISK_SPACE_CACHE.get(path)
        if cached_entry and time.time() - cached_entry["timestamp"] < _CACHE_TTL:
            return cached_entry["value"]

        available_space = await calculate_available_disk_space(path)
        # Store disk space in cache.
        _DISK_SPACE_CACHE[path] = {"value": available_space, "timestamp": time.time()}
        return available_space


async def _main():
    """Main function to print available disk space."""
    if len(sys.argv) < 2:
        print("Usage: python script.py <path>")
        sys.exit(1)

    path = sys.argv[1]
    available_space = await get_available_disk_space_cached(path)
    print(f"Available disk space (considering sparse files) at {path}: {available_space} bytes")


if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")
    asyncio.run(_main())
