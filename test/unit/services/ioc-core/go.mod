module github.com/DgHnG36/ioc-enrich-system/ioc-core/test/unit/services/ioc-core

go 1.24.2

require (
	github.com/DgHnG36/ioc-enrich-system/ioc-core v0.0.0
	github.com/DgHnG36/ioc-enrich-system/shared/go v0.0.0
	github.com/stretchr/testify v1.11.1
	google.golang.org/grpc v1.79.1
)

replace github.com/DgHnG36/ioc-enrich-system/ioc-core => ../../../../services/ioc-core

replace github.com/DgHnG36/ioc-enrich-system/shared/go => ../../../../shared/go
