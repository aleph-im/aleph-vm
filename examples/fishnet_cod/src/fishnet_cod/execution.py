import pandas as pd
from model import *


async def run_execution(execution: Execution) -> Optional[Execution]:
    async def set_failed(execution, reason):
        execution.status = ExecutionStatus.FAILED
        result = await Result.create(executionID=execution.id_hash, data=reason)
        execution.resultID = result.id_hash
        return await execution.upsert()

    assert isinstance(execution, Execution)
    if execution.status != ExecutionStatus.PENDING:
        return execution

    execution.status = ExecutionStatus.RUNNING
    await execution.upsert()

    try:
        try:
            algorithm = (await Algorithm.fetch(execution.algorithmID))[0]
        except IndexError:
            return await set_failed(
                execution, f"Algorithm {execution.algorithmID} not found"
            )

        try:
            exec(algorithm.code)
        except Exception as e:
            return await set_failed(execution, f"Failed to parse algorithm code: {e}")

        if "run" not in locals():
            return await set_failed(execution, "No run(df: DataFrame) function found")

        try:
            dataset = (await Dataset.fetch(execution.datasetID))[0]
        except IndexError:
            return await set_failed(
                execution, f"Dataset {execution.datasetID} not found"
            )

        timeseries = await Timeseries.fetch(dataset.timeseriesIDs)
        if len(timeseries) != len(dataset.timeseriesIDs):
            if len(timeseries) == 0:
                return await set_failed(
                    execution, f"Timeseries for dataset {dataset.id_hash} not found"
                )
            return await set_failed(
                execution,
                f"Timeseries incomplete: {len(timeseries)} out of {len(dataset.timeseriesIDs)} found",
            )

        try:
            # parse all timeseries as series and join them into a dataframe
            df = pd.concat(
                [
                    pd.Series(
                        [x[1] for x in ts.data],
                        index=[x[0] for x in ts.data],
                        name=ts.name,
                    )
                    for ts in timeseries
                ],
                axis=1,
            )
        except Exception as e:
            return await set_failed(execution, f"Failed to create dataframe: {e}")

        try:
            assert "run" in locals()
            result = locals()["run"](df)
        except Exception as e:
            return await set_failed(execution, f"Failed to run algorithm: {e}")

        result_message = await Result.create(
            executionID=execution.id_hash, data=str(result)
        )
        execution.status = ExecutionStatus.SUCCESS
        execution.resultID = result_message.id_hash
        await execution.upsert()
    except Exception as e:
        return await set_failed(execution, f"Unexpected error occurred: {e}")
    finally:
        del locals()["run"]
        return execution
