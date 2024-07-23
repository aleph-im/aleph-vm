FROM python:3.11

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     zip \
     && rm -rf /var/lib/apt/lists/*

RUN pip install 'fastapi==0.110.0' 'aiofiles==23.2.1' 'uvicorn==0.29.0' 'aleph-sdk-python==0.9.1'

WORKDIR /opt
ENV PYTHONPATH=/opt
EXPOSE 4021

COPY ./vm_connector /opt/vm_connector
CMD ["uvicorn", "vm_connector.main:app", "--host", "0.0.0.0", "--port", "4021", "--reload"]
