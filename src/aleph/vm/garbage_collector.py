"""Free disk space by removing unused volume from the hard drive to free up


This script allow to manually  list and remove volume linked to inactive VM
It fetches data from the scheduler and pyaleph main's node as to fetch information on the status of the VM.
Then display them to the user to determine if they can be removed safely.

Requires to be run as root.
"""

import os
import subprocess
from pathlib import Path

import requests

# following hashes are used in tests or debug VM, we can ignore them.
TEST_HASHES = [
    "fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_",
    "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
    "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca",
    "63faf8b5db1cf8d965e6a464a0cb8062af8e7df131729e48738342d956f29ace",
    "67705389842a0a1b95eaa408b009741027964edc805997475e95c505d642edd8",
    "ad67c6857d6319486794ec2a3d14b584ac7e6c27593f3172148e486dbd1e0e21",
    "850fa994dfa991ce4788dc728fef11608e8a77bb0e0b77aabd6678207b47d1b3",
]

api_server = [
    "https://api2.aleph.im",
    "https://api3.aleph.im",
    # 'https://official.aleph.cloud',
]

endpoint = "/api/v0/messages/"


def check_api(item_hash):
    """Check on which api the ITEM_HASH msg is available."""
    for api in api_server:
        response = requests.get(api + endpoint + item_hash)
        print(api + " ", end="")
        print(response.status_code, end="")
        j = response.json()
        print(" " + j["status"], end="")
        print()


p = Path("/var/lib/aleph/vm/volumes/persistent")
# print current size
os.system(" ".join(["df", "-h", str(p)]))

# Before anything check that we can reach the api server and the scheduler server
res = requests.get("https://api2.aleph.im/api/v0/info/public.json")
assert res.status_code == 200
res = requests.get("https://scheduler.api.aleph.cloud/api/v0/plan")
assert res.status_code == 200

volume_dirs = list(p.glob("*"))
for i, f in enumerate(reversed(volume_dirs)):
    if not f.is_dir():
        continue
    item_hash = f.name
    print(f"= {i}/{len(volume_dirs) -1} {item_hash}")
    if item_hash in TEST_HASHES:
        print("Test VM, skipping")
        continue

    res = requests.get(f"https://api2.aleph.im/api/v0/messages/{item_hash}")

    if res.status_code == 404:
        print("Not found on API server")
        continue
    message = res.json()
    message_status = message.get("status")
    # if message_status == "forgotten" or message_status == "rejected":
    #     print(f"{item_hash} status: {j.message_status('status')}")
    #     continue
    # print(f"{item_hash} status: {j.message_status('status')}")
    sender = message["message"]["sender"]
    print(f"Sender {sender}. State: {message_status}")
    if not message["message"]["type"] == "INSTANCE":
        print("Type: ", message["message"]["type"], "not an instance")
        continue
    scheduler_res = requests.get(f"https://scheduler.api.aleph.cloud/api/v0/allocation/{item_hash}")
    schedule = None

    if scheduler_res.status_code == 404:
        print("Not found on scheduler plan")
    else:
        schedule = scheduler_res.json()
        print(f"scheduled on {schedule['node']['node_id']}")

    balance = requests.get(f"https://api2.aleph.im/api/v0/addresses/{sender}/balance").json()
    print(f"User balance: {balance['balance']:.2f}, locked amount {balance['locked_amount']:.2f}")
    # print(balance)

    # check if process is still running

    proc_ret = subprocess.run(
        f"systemctl status aleph-vm-controller@{item_hash}.service --no-pager",
        shell=True,
        capture_output=True,
        check=False,
    )
    exit_code = proc_ret.returncode
    if exit_code == 0:
        proc_status = "running"
    elif exit_code == 3:
        proc_status = "stopped"
    else:
        proc_status = "error"
        print("Unknown process state", exit_code)
    # to remove

    if proc_status != "running":
        # not running and forgotten

        if message_status == "forgotten" or message_status == "rejected":
            print("Recommendation: remove, process not running and message rejected or forgotten")
        else:
            print("Process stopped")
            # print(f"balances: {balance['balance']}, locked amount {balance['locked_amount']}'")

        while True:
            inp = input("Do you want to delete y/n ? More info (h) [n] ").lower()
            if inp in ["y", "yes"]:
                os.system(f"dmsetup remove {item_hash}_base")
                os.system(f"dmsetup remove {item_hash}_rootfs")
                os.system(f"rm -r {f.absolute()}")
                # close all loop device
                os.system(
                    "sudo losetup -l | grep 'persistent' | grep deleted | awk  '{print $1}' | sudo xargs losetup -d {}"
                )
                break
            elif inp == "h":
                print(proc_ret.stdout.decode())
                check_api(item_hash)
                print(f"https://api2.aleph.im/api/v0/messages/{item_hash}")
                print(f"https://api2.aleph.im/api/v0/addresses/{sender}/balance")
            else:
                break

    else:
        print("process is running, do not delete")


# print current size.
print("Size after")
os.system(" ".join(["df", "-h", str(p)]))
