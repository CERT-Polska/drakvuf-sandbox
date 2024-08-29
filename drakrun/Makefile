WEB_SOURCE_FILES := $(find drakrun/web/frontend/src -name '*.js' -or -name '*.css')
PYTHON_SOURCE_FILES := $( find drakrun -name '*.py' ) drakrun/data pyproject.toml MANIFEST.in requirements.txt setup.py

.PHONY: all
all: dist/*.whl

dist/*.whl: $(PYTHON_SOURCE_FILES) drakrun/web/frontend/build drakrun/tools/get-explorer-pid drakrun/tools/test-altp2m
	python3 setup.py bdist_wheel

drakrun/web/frontend/build: drakrun/web/frontend/node_modules $(WEB_SOURCE_FILES) drakrun/web/frontend/public
	cd drakrun/web/frontend ; npm run build

drakrun/web/frontend/node_modules: drakrun/web/frontend/package.json drakrun/web/frontend/package-lock.json
	cd drakrun/web/frontend ; npm ci

drakrun/tools/get-explorer-pid: drakrun/tools/get-explorer-pid.c
	gcc $< -o $@ -lvmi `pkg-config --cflags --libs glib-2.0`

drakrun/tools/test-altp2m: drakrun/tools/test-altp2m.c
	gcc $< -o $@ -lvmi `pkg-config --cflags --libs glib-2.0`

.PHONY: clean
clean:
	rm -rf dist drakvuf_sandbox.egg-info build
	rm -rf drakrun/web/frontend/build drakrun/web/frontend/node_modules
	rm -f drakrun/tools/get-explorer-pid drakrun/tools/test-altp2m

.PHONY: install
install: all
	pip install dist/*.whl
