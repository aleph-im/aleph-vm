from fastapi.testclient import TestClient

from .main import app
from .requests import *
from fishnet_cod import *

client = TestClient(app)


def test_full_request_execution_flow_with_own_dataset():
    req: UploadTimeseriesRequest = UploadTimeseriesRequest(
        timeseries=[
            TimeseriesItem(name="test", owner="test", data=[[1.0, 2.0], [3.0, 4.0]])
        ]
    )
    req_body = req.dict()
    response = client.put("/timeseries/upload", json=req_body)
    assert response.status_code == 200
    assert response.json()[0]["id_hash"] is not None
    timeseries_id = response.json()[0]["id_hash"]

    req: UploadDatasetRequest = UploadDatasetRequest(
        name="test", owner="test", ownsAllTimeseries=True, timeseriesIDs=[timeseries_id]
    )
    response = client.put("/datasets/upload", json=req.dict())
    assert response.status_code == 200
    assert response.json()["id_hash"] is not None
    dataset_id = response.json()["id_hash"]

    req: UploadAlgorithmRequest = UploadAlgorithmRequest(
        name="test", desc="test", owner="test", code="test"
    )
    response = client.put("/algorithms/upload", json=req.dict())
    assert response.status_code == 200
    assert response.json()["id_hash"] is not None
    algorithm_id = response.json()["id_hash"]

    req: RequestExecutionRequest = RequestExecutionRequest(
        algorithmID=algorithm_id, datasetID=dataset_id, owner="test"
    )
    response = client.post("/executions/request", json=req.dict())
    assert response.status_code == 200
    assert response.json()["execution"]["status"] == ExecutionStatus.PENDING


def test_requests_approval_deny():
    req: TimeseriesItem = TimeseriesItem(
        name="Approve_test", owner="test", available=True, data=[[1.0, 2.0], [3.0, 4.0]]
    )
    req_body = req.dict()
    response = client.post("/Timeseries", json=req_body)
    assert response.status_code == 200
    assert response.json()["id_hash"] is not None
    timeseries_id = response.json()["id_hash"]

    req: UploadDatasetRequest = UploadDatasetRequest(
        name="Approve_test",
        owner="test",
        ownsAllTimeseries=True,
        timeseriesIDs=[timeseries_id],
    )
    response = client.put("/datasets/upload", json=req.dict())
    assert response.status_code == 200
    assert response.json()["id_hash"] is not None
    dataset_id = response.json()["id_hash"]

    req: UploadAlgorithmRequest = UploadAlgorithmRequest(
        name="Approve_test", desc="Approve_test", owner="Approve_test", code="test"
    )
    response = client.put("/algorithms/upload", json=req.dict())
    assert response.status_code == 200
    assert response.json()["id_hash"] is not None
    algorithm_id = response.json()["id_hash"]
    print(algorithm_id)


def test_execution_dataset():
    dataset_Id = "5fecb379a0efdbd88a3d06f9b587dd3161dc8da6a8497f280f86bb3aa05eea94"
    response = client.get(f"/executions/{dataset_Id}")
    assert response.json()
    data = response.json()
    print("data", data)

def test_dataset():
    page = 1
    page_size = 1
    response = client.get('/datasets')

