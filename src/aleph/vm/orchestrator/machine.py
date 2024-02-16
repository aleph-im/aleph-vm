import json
import re
import subprocess
from functools import lru_cache

import psutil


@lru_cache
def get_hardware_info():
    lshw = subprocess.Popen(["lshw", "-sanitize", "-json"], stdout=subprocess.PIPE, shell=False)
    output, _ = lshw.communicate()
    data = json.loads(output)

    hw_info = {}

    for hw in data["children"][0]["children"]:
        if hw["id"] == "cpu":
            hw_info["cpu"] = hw
        elif hw["class"] == "memory" and hw["id"] == "memory":
            hw_info["memory"] = hw

    return hw_info


@lru_cache
def get_cpu_info():
    hw = get_hardware_info()

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


@lru_cache
def get_memory_info():
    hw = get_hardware_info()
    mem_info = hw["memory"]

    memory_type = ""
    memory_clock = ""

    for bank in mem_info["children"]:
        memory_clock = bank["clock"]
        try:
            memory_type = re.search("(DDR[2-6])", bank["description"]).group(0)
            break
        except:
            pass

    return {
        "size": mem_info["size"],
        "units": mem_info["units"],
        "type": memory_type,
        "clock": memory_clock,
        "clock_units": "Hz",
    }
