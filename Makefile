all:
	docker build -t cbox_rpm_builder_img .
	docker run --rm -it -v ${CURDIR}:/root/go/src/github.com/cernbox/cboxredirectd -w /root/go/src/github.com/cernbox/cboxredirectd cbox_rpm_builder_img bash -lc "make rpm"

rpm:
	go get ./...
	go build ./...
	chown -R root:root .
	cd cboxredirectd && make rpm