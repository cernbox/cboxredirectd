all:
	go get ./...
	go build ./...
	chown -R root:root .
	cd cboxredirectd && make rpm