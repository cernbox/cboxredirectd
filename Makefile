pwd = $(shell pwd)

default: all
on:
	GO11MODULE=on
all: on
	docker build -t cbox_rpm_builder_img .
	docker run --rm -it -v ${pwd}:/root/cboxredirectd cbox_rpm_builder_img bash -lc "find && cd /root/cboxredirectd && make rpm"

rpm: on
	cd cboxredirectd && go build
	chown -R root:root .
	cd cboxredirectd && make rpm