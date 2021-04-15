from typing import Optional

from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/run/{item_id}")
def read_item(item_id: str, q: Optional[str] = None):
    return {"item_id": item_id, "q": q}


@app.post("/run/{item_id}")
def read_item_post(item_id: str, q: Optional[str] = None):
    return {"item_id_post": item_id, "q": q}
