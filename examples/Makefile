all: example_fastapi_2.zip data.tgz

clean:
	rm example_fastapi_2.zip
	rm data.tgz

example_fastapi_2.zip:
	zip -r example_fastapi_2.zip example_fastapi_2

data.tgz:
	tar -cvzf data.tgz data

example_pip.squashfs:
	rm -fr /opt/python
	pip3 install -t /opt/requirements -r example_pip/requirements.txt
	mksquashfs /opt/requirements requirements.squashfs
