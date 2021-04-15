"""
This module is in charge of providing the source code corresponding to a 'code id'.

In this prototype, it returns a hardcoded example.
In the future, it should connect to an Aleph node and retrieve the code from there.
"""
import os.path
from typing import Tuple

class Encoding:
    plain = 'plain'
    zip = 'zip'


def read_relative_file(path):
    abspath = os.path.abspath(
        os.path.join(__file__, path)
    )
    with open(abspath, 'rb') as f:
        return f.read()


codes = {
    'fastapi': (read_relative_file('../../examples/example_fastapi_1.py'), 'app', Encoding.plain),
    'fastapi-pyz': (read_relative_file('../../examples/example_fastapi_2.pyz'),
                    'example_fastapi_2:app', Encoding.zip),
}

def get_code(code_id) -> Tuple[bytes, str, str]:
    return codes[code_id]
