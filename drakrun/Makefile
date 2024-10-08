WEB_SOURCE_FILES := $(wildcard *.js *.css)
PYTHON_SOURCE_FILES := $( wildcard *.py ) drakrun/data pyproject.toml MANIFEST.in requirements.txt setup.py

.PHONY: all
all: dist/*.whl

dist/*.whl: $(PYTHON_SOURCE_FILES) drakrun/web/frontend/build drakrun/tools/get-explorer-pid drakrun/tools/test-altp2m drakrun/tools/test-hvm64-example
	rm -f dist/*.whl
ifndef DIST
	DRAKRUN_VERSION_TAG=$(shell git rev-parse --short HEAD) python3 setup.py bdist_wheel
else
	python3 setup.py bdist_wheel
endif

drakrun/web/frontend/build: drakrun/web/frontend/node_modules $(WEB_SOURCE_FILES) drakrun/web/frontend/public
	cd drakrun/web/frontend ; npm run build

drakrun/web/frontend/node_modules: drakrun/web/frontend/package.json drakrun/web/frontend/package-lock.json
	cd drakrun/web/frontend ; npm ci

drakrun/tools/get-explorer-pid: drakrun/tools/get-explorer-pid.c
	gcc $< -o $@ -lvmi `pkg-config --cflags --libs glib-2.0`

drakrun/tools/test-altp2m: drakrun/tools/test-altp2m.c
	gcc $< -o $@ -lvmi `pkg-config --cflags --libs glib-2.0`

drakrun/tools/test-hvm64-example: drakrun/tools/xtf
	$(MAKE) -C drakrun/tools/xtf
	cp drakrun/tools/xtf/tests/example/test-hvm64-example drakrun/tools/test-hvm64-example

.PHONY: clean
clean:
	rm -rf dist drakvuf_sandbox.egg-info build
	rm -rf drakrun/web/frontend/build drakrun/web/frontend/node_modules
	rm -f drakrun/tools/get-explorer-pid drakrun/tools/test-altp2m

.PHONY: install
install: all
	pip install dist/*.whl
