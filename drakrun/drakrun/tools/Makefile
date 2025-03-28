all: get-explorer-pid

get-explorer-pid: get-explorer-pid.c
	gcc $< -o $@ -lvmi `pkg-config --cflags --libs glib-2.0`
