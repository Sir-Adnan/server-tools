SHELL := /usr/bin/env bash

.PHONY: build lint fmt test clean

build:
	bash build.sh

lint: build
	shellcheck dist/server-tools.sh build.sh tests/smoke.sh
	shfmt -i 2 -ci -d src build.sh tests

fmt:
	shfmt -i 2 -ci -w src build.sh tests

test:
	bash tests/smoke.sh

clean:
	rm -f dist/server-tools.sh
