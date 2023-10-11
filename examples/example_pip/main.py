import pandas as pandas
from fastapi import FastAPI, Response

app = FastAPI()


@app.get("/")
async def root():
    data = range(10)
    df = pandas.DataFrame(data)
    return Response(content=df.to_html(), media_type="text/html")
