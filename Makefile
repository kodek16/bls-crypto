PHONY: test

test: dep gen
	go test -v ./test

gen:
	cd src;go generate

dep:
	go mod tidy
