VERSION= $(shell cat ./VERSION)
GO?= go
NPM?= npm
DOCKER_REPO?= git.mdoetsch.de/matze/anubis
DOCKER_TAG?= latest

.PHONY: build assets deps lint prebaked-build test docker

all: build

deps:
	$(NPM) ci
	$(GO) mod download

assets: PATH:=$(PWD)/node_modules/.bin:$(PATH)
assets: deps
	$(GO) generate ./...
	./web/build.sh
	./xess/build.sh

build: assets
	$(GO) build -o ./var/anubis ./cmd/anubis
	$(GO) build -o ./var/robots2policy ./cmd/robots2policy
	@echo "Anubis is now built to ./var/anubis"

lint: assets
	$(GO) vet ./...
	$(GO) tool staticcheck ./...
	
prebaked-build:
	$(GO) build -o ./var/anubis -ldflags "-X 'github.com/TecharoHQ/anubis.Version=$(VERSION)'" ./cmd/anubis
	$(GO) build -o ./var/robots2policy -ldflags "-X 'github.com/TecharoHQ/anubis.Version=$(VERSION)'" ./cmd/robots2policy

test: assets
	$(GO) test ./...

docker:
	docker build -t $(DOCKER_REPO):$(DOCKER_TAG) --build-arg VERSION=$(VERSION) . --push
#	docker push $(DOCKER_REPO):$(DOCKER_TAG)
