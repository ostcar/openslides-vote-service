build-dev:
	docker build . --target development --tag openslides-vote-dev

run-tests:
	docker build . --target testing --tag openslides-vote-test
	docker run openslides-vote-test

proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=require_unimplemented_servers=false:. --go-grpc_opt=paths=source_relative decrypt/grpc/decrypt.proto
