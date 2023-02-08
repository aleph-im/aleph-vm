all: example_fastapi.zip data.tgz

clean:
	rm example_fastapi.zip
	rm data.tgz

fishnet_executor:
	zip -r fishnet_executor.zip fishnet_executor
	aleph program fishet_executor.zip fishnet_executor:app

data.tgz:
	tar -cvzf data.tgz data

fishnet_api.squashfs:
	rm -fr /opt/python
	pip3 install -t /opt/requirements -r fishnet_api/requirements.txt
	mksquashfs /opt/requirements requirements.squashfs
