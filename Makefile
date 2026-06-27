BENCH_TARGET ?= http://localhost:80
NGINX_ACCESS_LOG ?= webapp/log/nginx/access.log
NGINX_CONTAINER_ACCESS_LOG ?= /var/log/nginx/access.log
DOCKER_COMPOSE ?= docker compose -f webapp/compose.yml
ALP_MATCHER ?= ^/image/[0-9]+\.(jpg|png|gif)$$,^/posts/[0-9]+$$

.PHONY: init bench alp bench-alp truncate-nginx-log
init: webapp/sql/dump.sql.bz2 benchmarker/userdata/img

bench: benchmarker/bin/benchmarker
	$(MAKE) truncate-nginx-log
	benchmarker/bin/benchmarker -t "$(BENCH_TARGET)" -u benchmarker/userdata

alp:
	alp ltsv --file $(NGINX_ACCESS_LOG) --sort sum --reverse --matching-groups '$(ALP_MATCHER)'

bench-alp: bench alp

truncate-nginx-log:
	$(DOCKER_COMPOSE) exec -T nginx sh -c 'truncate -s 0 $(NGINX_CONTAINER_ACCESS_LOG) || : > $(NGINX_CONTAINER_ACCESS_LOG)'

benchmarker/bin/benchmarker:
	$(MAKE) -C benchmarker

webapp/sql/dump.sql.bz2:
	cd webapp/sql && \
	curl -L -O https://github.com/catatsuy/private-isu/releases/download/img/dump.sql.bz2

benchmarker/userdata/img.zip:
	cd benchmarker/userdata && \
	curl -L -O https://github.com/catatsuy/private-isu/releases/download/img/img.zip

benchmarker/userdata/img: benchmarker/userdata/img.zip
	cd benchmarker/userdata && \
	unzip -qq -o img.zip
