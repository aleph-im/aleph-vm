import asyncio
import json
import re

import psutil


async def get_hardware_info():
    lshw = await asyncio.create_subprocess_shell(
        "lshw -sanitize -json", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    output, _ = await lshw.communicate()
    data = json.loads(output)

    hw_info = {"cpu": None, "memory": None}

    for hw in data["children"][0]["children"]:
        if hw["id"] == "cpu":
            hw_info["cpu"] = hw
        elif hw["class"] == "memory" and hw["id"] == "memory":
            hw_info["memory"] = hw

    return hw_info


def get_cpu_info(hw):
    cpu_info = hw["cpu"]
    architecture = cpu_info["width"]

    if "x86_64" in cpu_info["capabilities"] or "x86-64" in cpu_info["capabilities"]:
        architecture = "x86_64"
    elif "arm64" in cpu_info["capabilities"] or "arm-64" in cpu_info["capabilities"]:
        architecture = "arm64"

    vendor = cpu_info["vendor"]
    # lshw vendor implementation => https://github.com/lyonel/lshw/blob/15e4ca64647ad119b69be63274e5de2696d3934f/src/core/cpuinfo.cc#L308

    if "Intel Corp" in vendor:
        vendor = "GenuineIntel"
    elif "Advanced Micro Devices [AMD]" in vendor:
        vendor = "AuthenticAMD"

    return {
        "architecture": architecture,
        "vendor": vendor,
        "model": cpu_info["product"],
        "frequency": cpu_info["capacity"],
        "count": psutil.cpu_count(),
    }


def get_memory_info(hw):
    mem_info = hw["memory"]

    memory_type = ""
    memory_clock = ""

    for bank in mem_info["children"]:
        memory_clock = bank["clock"]
        if "description" in bank:
            matched = re.search("(DDR[2-6])", bank["description"])
            if matched:
                memory_type = matched.group(0)
                break
            else:
                pass

    return {
        "size": mem_info["size"],
        "units": mem_info["units"],
        "type": memory_type,
        "clock": memory_clock,
        "clock_units": "Hz",
    }
