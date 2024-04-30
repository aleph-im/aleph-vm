#!/usr/bin/env python3

"""
Set the version number of a package based on the current repository:

Use the tag it one is available for the current commit.
Else default to the short commit id, prefixed by the name of the current branch.

Pass the path to the target file to edit in argument.
"""

import os.path
import re
import subprocess
import sys

script_path, *args, format_, target_file_path = sys.argv

for arg in args:
    if arg not in ("--inplace", "--stdout"):
        print(
            "Usage: version_from_git.py [target FILE PATH] [FORMAT] [OPTION...]\n\n"
            "set the version number of a Debian package based on the current git commit\n\n"
            "supported formats are 'deb' and 'setup.py'\n\n"
            "  --help       print this message\n"
            "  --inplace    edit file in place\n"
            "  --inplace    edit file in place\n"
            "  --stdout     print the result on stdout\n"
        )
        sys.exit(1)

if not os.path.isfile(target_file_path):
    print(f"No such file: '{target_file_path}'")
    sys.exit(2)


def get_git_version():
    output = subprocess.check_output(("git", "describe", "--tags"))
    return output.decode().strip()


version = get_git_version()

with open(target_file_path) as target_file:
    target_content = target_file.read()

if format_ == "deb":
    updated_content = re.sub(r"(Version:)\w*(.*)", f"\\1 {version}", target_content)
elif format_ == "setup.py":
    updated_content = re.sub(r"(version)\w*=(.*)'", f"\\1='{version}'", target_content)
elif format_ == "__version__":
    updated_content = re.sub(r"(__version__)\w*(.*)", f"\\1 = '{version}'", target_content)
else:
    print(f"Format must be 'deb', 'setup.py' or '__version__', not '{format_}'")

if "--inplace" in args:
    with open(target_file_path, "w") as target_file:
        target_file.write(updated_content)

if "--stdout" in args:
    print(updated_content)
