all: get-explorer-pid test-altp2m
	

get-explorer-pid: get-explorer-pid.c
	gcc $< -o $@ -lvmi `pkg-config --cflags --libs glib-2.0`


test-altp2m: test-altp2m.c
	gcc $< -o $@ -lvmi `pkg-config --cflags --libs glib-2.0`

test-hvm64-example: xtf
	$(MAKE) -C xtf
	cp xtf/tests/example/test-hvm64-example .
