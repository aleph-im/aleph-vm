FROM python:3.13

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     zip \
     && rm -rf /var/lib/apt/lists/*

RUN pip install 'fastapi==0.115.11' 'aiofiles==24.1.0' 'uvicorn==0.34.0' 'aleph-sdk-python==1.4.0' 'setuptools==76.0.0'

WORKDIR /opt
ENV PYTHONPATH=/opt
EXPOSE 4021

COPY ./vm_connector /opt/vm_connector
CMD ["uvicorn", "vm_connector.main:app", "--host", "0.0.0.0", "--port", "4021", "--reload"]
