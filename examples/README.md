# Creating and running Fishnet API

In this example, we will cover how to develop and run a small webapp based on
on [FastAPI](https://fastapi.tiangolo.com/).

## Initial setup
Install the FastAPI library and Uvicorn: 
```shell
pip install -r ./fishnet_api/requirements.txt
```

Uvicorn is used to run ASGI compatible web applications, such as the `app`
web application from the example above. You need to specify it the name of the
Python module to use and the name of the app:
```shell
python -m uvicorn fishnet_api:app --reload
```

Then open the app in a web browser on http://localhost:8000

> Tip: With `--reload`, Uvicorn will automatically reload your code upon changes  

## Upload on Aleph

The same `app` we just used with Gunicorn can be used by Aleph to run 
the web app, since Aleph attempts to be compatible with 
[ASGI](https://asgi.readthedocs.io/ASGI).

To upload the app, we can use the `aleph` command line tool. 
```shell
aleph program fishnet_api app
```

### TODO:
In order to make this fully work, we need to create an immutable volume which contains
the python modules required by the app, or create a `Dockerfile` which installs the
required modules as soon as the VM is deployed.

## Testing

Open the HTTP interface of a node running the VM Supervisor:

http://ip-of-supervisor:4020/vm/{message_hash}/
