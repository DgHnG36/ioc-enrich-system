.PHONY: all generate go python clean

PROTO_DIR := .
PROTO_FILES := $(shell find $(PROTO_DIR) -type f -name "*.proto")

GO_OUT := ../shared/go
PY_OUT := ../shared/python

GO_MODULE := github.com/DgHnG36/ioc_enrichment_service/shared/go

all: generate

generate: go python

go:
	@echo "==> Generating Go protobuf..."
	@mkdir -p $(GO_OUT)
	@protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GO_OUT) \
		--go_opt=module=$(GO_MODULE) \
		--go-grpc_out=$(GO_OUT) \
		--go-grpc_opt=module=$(GO_MODULE) \
		$(PROTO_FILES)
	@echo "==> Go protobuf generated"

python:
	@echo "==> Generating Python protobuf..."
	@mkdir -p $(PY_OUT)
	@python3 -m grpc_tools.protoc \
		--proto_path=$(PROTO_DIR) \
		--python_out=$(PY_OUT) \
		--grpc_python_out=$(PY_OUT) \
		$(PROTO_FILES)
	@find $(PY_OUT) -type d -exec touch {}/__init__.py \;
	@echo "==> Python protobuf generated"

clean:
	@echo "==> Cleaning generated code"
	@rm -rf $(GO_OUT)/*
	@rm -rf $(PY_OUT)/*