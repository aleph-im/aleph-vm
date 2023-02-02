from fastapi.testclient import TestClient
<<<<<<< HEAD

from .main import app
from .model import *
from .requests import *
=======
from .main import app
from .requests import *
from .model import *
>>>>>>> dd7aec7b8ceac4ecffade75250288b1fd3f622c0

client = TestClient(app)


def test_full_request_execution_flow_with_own_dataset():
    req: UploadTimeseriesRequest = UploadTimeseriesRequest(timeseries=[
        TimeseriesItem(
            name='test',
            owner='test',
            data=[[1.0, 2.0], [3.0, 4.0]]
        )]
    )
    req_body = req.dict()
    response = client.put('/timeseries/upload', json=req_body)
    assert response.status_code == 200
    assert response.json()[0]['id_hash'] is not None
    timeseries_id = response.json()[0]['id_hash']

    req: UploadDatasetRequest = UploadDatasetRequest(
        name='test',
        owner='test',
        ownsAllTimeseries=True,
        timeseriesIDs=[timeseries_id]
    )
    response = client.put('/datasets/upload', json=req.dict())
    assert response.status_code == 200
    assert response.json()['id_hash'] is not None
    dataset_id = response.json()['id_hash']

    req: UploadAlgorithmRequest = UploadAlgorithmRequest(
        name='test',
        desc='test',
        owner='test',
        code='test'
    )
    response = client.put('/algorithms/upload', json=req.dict())
    assert response.status_code == 200
    assert response.json()['id_hash'] is not None
    algorithm_id = response.json()['id_hash']

    req: RequestExecutionRequest = RequestExecutionRequest(
        algorithmID=algorithm_id,
        datasetID=dataset_id,
        owner='test'
    )
    response = client.post('/executions/request', json=req.dict())
    assert response.status_code == 200
    assert response.json()['execution']['status'] == ExecutionStatus.PENDING


def test_requests_approval_deny():
    req: TimeseriesItem = TimeseriesItem(
            name='Approve_test',
            owner='test',
            available = True,
            data=[[1.0, 2.0], [3.0, 4.0]]
        )
    req_body = req.dict()
    response = client.post('/Timeseries', json=req_body)
    assert response.status_code == 200
    assert response.json()['id_hash'] is not None
    timeseries_id = response.json()['id_hash']

    req: UploadDatasetRequest = UploadDatasetRequest(
        name='Approve_test',
        owner='test',
        ownsAllTimeseries=True,
        timeseriesIDs=[timeseries_id]
    )
    response = client.put('/datasets/upload', json=req.dict())
    assert response.status_code == 200
    assert response.json()['id_hash'] is not None
    dataset_id = response.json()['id_hash']

    req: UploadAlgorithmRequest = UploadAlgorithmRequest(
        name='Approve_test',
        desc='Approve_test',
        owner='Approve_test',
        code='test'
    )
    response = client.put('/algorithms/upload', json=req.dict())
    assert response.status_code == 200
    assert response.json()['id_hash'] is not None
    algorithm_id = response.json()['id_hash']
    print(algorithm_id)





=======
>>>>>>> dd7aec7b8ceac4ecffade75250288b1fd3f622c0
