
podman-prepare:
	podman build -t aleph-example-js .

podman-publish:
	podman run --rm -ti aleph-example-js make publish

podman-client:
	podman rmi aleph-example-js

docker-prepare:
	docker build -t aleph-example-js .

docker-publish:
	docker run --rm -ti aleph-example-js make publish

publish:
	chmod +x ./src/run.sh
	aleph program ./src "run.sh"
