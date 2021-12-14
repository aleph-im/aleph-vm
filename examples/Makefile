all: example_fastapi.zip data.tgz

clean:
	rm example_fastapi.zip
	rm data.tgz

example_fastapi.zip:
	zip -r example_fastapi.zip example_fastapi

data.tgz:
	tar -cvzf data.tgz data

example_pip.squashfs:
	rm -fr /opt/python
	pip3 install -t /opt/requirements -r example_pip/requirements.txt
	mksquashfs /opt/requirements requirements.squashfs
