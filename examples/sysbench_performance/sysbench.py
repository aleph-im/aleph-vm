import multiprocessing
import re
import subprocess

from fastapi import FastAPI

"""
Runtime: 9a7e0c4bc155b7f5d8bb589f95e13be562981a18b53a1b0a2ba1db91264b8301
"""


class Sysbench:

    def cpu_speed(self, prime=20000, time=60, threads=None):
        arg1 = "--cpu-max-prime=" + str(prime)
        arg2 = "--time=" + str(time)
        if not threads:
            threads = multiprocessing.cpu_count()

        argt = "--threads=" + str(threads)

        cpu_bench = subprocess.Popen(["sysbench", "cpu", arg1, arg2, argt, "run"], stdout=subprocess.PIPE, shell=False)
        output, err = cpu_bench.communicate()
        score = -1
        for line in output.decode().split("\n"):
            if "events per second" in line:
                score = re.findall("\d+\.?\d+", line)[0]
                break
        return float(score)

    def memory_speed(self, mode="read", mem_block_size="2G",
                     mem_total_size="20G"
                     ):
        arg1 = "--memory-block-size=" + str(mem_block_size)
        arg2 = "--memory-total-size=" + str(mem_total_size)
        arg3 = "--memory-oper=" + str(mode)

        memory_bench = subprocess.Popen(["sysbench", "memory", arg1, arg2, arg3, "run"], stdout=subprocess.PIPE, shell=False)
        output, err = memory_bench.communicate()
        speed = -1
        for line in output.decode().split("\n"):
            if "MiB/sec" in line:
                speed_str = re.findall("\d+\.?\d+ MiB/sec", line)[0]
                speed = speed_str.split(" ")[0]
                break
        return float(speed)

    def disk_speed(self, file_total_size="1G", file_num="32",
                   file_block_size="16M"
                   ):
        arg1 = "--file-total-size=" + str(file_total_size)
        arg2 = "--file-num=" + str(file_num)
        arg3 = "--file-block-size=" + str(file_block_size)

        # Random read/write
        file_test_mode = "rndrw"
        arg4 = "--file-test-mode=" + str(file_test_mode)
        arg5 = "--time=60"
        disk_prepare = subprocess.Popen(["sysbench", "fileio", arg1, arg2, arg3, arg4, arg5, "prepare"], stdout=subprocess.PIPE, shell=False, cwd="/sysbench")
        disk_prepare.communicate()
        disk_bench = subprocess.Popen(["sysbench", "fileio", arg1, arg2, arg3, arg4, arg5, "run"], stdout=subprocess.PIPE, shell=False, cwd="/sysbench")
        output, err = disk_bench.communicate()
        read_speed = -1
        write_speed = -1
        for line in output.decode().split("\n"):
            if "read, MiB/s" in line:
                read_speed = re.findall("read, MiB/s:\s+(\d+\.?\d+)", line)[0]
            if "written, MiB/s" in line:
                write_speed = re.findall("written, MiB/s:\s+(\d+\.?\d+)", line)[0]

        disk_cleanup = subprocess.Popen(["sysbench", "fileio", arg1, arg2, arg3, arg4, arg5, "cleanup"], stdout=subprocess.PIPE, shell=False, cwd="/sysbench")
        disk_cleanup.communicate()

        return (float(read_speed), float(write_speed))


app = FastAPI()


@app.get("/sysbench/cpu")
async def sysbench_cpu():
    sysbench = Sysbench()
    prime = 20000
    time = 60
    mode = "single core"
    score = sysbench.cpu_speed(prime, time, 1)

    return {
        "mode": mode,
        "prime": prime,
        "time": time,
        "unit": "sysbench",
        "score": score
    }


@app.get("/sysbench/memory")
async def sysbench_memory():
    sysbench = Sysbench()
    mem_block_size = "2G"
    mem_total_size = "20G"

    write_speed = sysbench.memory_speed("write", mem_block_size, mem_total_size)
    read_speed = sysbench.memory_speed("read", mem_block_size, mem_total_size)

    return {
        "unit": "MiB/sec",
        "read_speed": read_speed,
        "write_speed": write_speed
    }


@app.get("/sysbench/disk")
async def sysbench_disk():
    sysbench = Sysbench()

    read_speed, write_speed = sysbench.disk_speed()

    return {
        "unit": "MiB/sec",
        "read_speed": read_speed,
        "write_speed": write_speed
    }
