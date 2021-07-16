FROM python:3.9

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     zip \
     && rm -rf /var/lib/apt/lists/*

RUN pip install fastapi aiofiles uvicorn aleph-client eth-account

WORKDIR /opt
ENV PYTHONPATH=/opt
EXPOSE 4021

COPY ./vm_connector /opt/vm_connector
CMD ["uvicorn", "vm_connector.main:app", "--host", "0.0.0.0", "--port", "4021", "--reload"]
