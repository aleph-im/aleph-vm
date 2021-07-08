# Creating and running an Aleph Program

In this example, we will cover how to develop and run a small webapp based on
on [FastAPI](https://fastapi.tiangolo.com/).

## Initial setup

Let's start by creating a package for our app: 
Create a directory named `example_fastapi_2` 
and an empty file named `__init__.py` file within the directory.
```
example_fastapi_2/
example_fastapi_2/__init__.py
```

The copy the example from the FastAPI tutorial in `__init__.py`:
```python
from typing import Optional

from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def index():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Optional[str] = None):
    return {"item_id": item_id, "q": q}
```

Install the FastAPI library and Uvicorn: 
```shell
pip install fastapi uvicorn
```

Uvicorn is used to run ASGI compatible web applications, such as the `app`
web application from the example above. You need to specify it the name of the
Python module to use and the name of the app:
```shell
uvicorn example_fastapi_2:app --reload
```

Then open the app in a web browser on http://localhost:8000

> Tip: With `--reload`, Uvicorn will automatically reload your code upon changes  

## Upload on Aleph

The same `app` we just used with Gunicorn can be used by Aleph to run 
the web app, since Aleph attempts to be compatible with 
[ASGI](https://asgi.readthedocs.io/ASGI).

To achieve this, we need to follow the following steps:

### 1. Create a zip archive containing the app

```shell
zip -r example_fastapi_2.zip example_fastapi_2
```

### 2. Store the zip archive on Aleph

You can use [aleph-client](https://github.com/aleph-im/aleph-client) to achieve this.
See `examples/store.py`.

### 3. Create an Aleph message describing how to run your app

See [this example](https://explorer.aleph.im/address/ETH/0x9319Ad3B7A8E0eE24f2E639c40D8eD124C5520Ba/message/POST/91c83eff3ba23d6b501a2aa3c4364ec235eb8283b6fa8ac20d235642a48791b8).

In the `code` section, replace the `ref` with the `item_hash` of the messages
storing your code.

Update the `entrypoint` field according to your app if necessary.

## Testing

Open the HTTP interface of a node running the VM Supervisor:

http://ip-of-supervisor:4020/vm/{message_hash}/
