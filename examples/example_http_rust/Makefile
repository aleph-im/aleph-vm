
podman-prepare:
	podman build -t aleph-example-rust .

podman-publish:
	podman run --rm -ti aleph-example-rust make publish

docker-prepare:
	docker build -t aleph-example-rust .

docker-publish:
	docker run --rm -ti aleph-example-rust make publish

publish:
	cargo build --release
	mkdir -p ./dist
	cp target/release/example_http_rust ./dist/
	aleph program upload ./dist example_http_rust
