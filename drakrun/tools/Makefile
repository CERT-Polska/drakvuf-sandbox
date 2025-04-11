all: get-explorer-pid drakshell/drakshell

get-explorer-pid: get-explorer-pid.c
	gcc $< -o $@ -lvmi `pkg-config --cflags --libs glib-2.0`

drakshell/drakshell:
	$(MAKE) -C drakshell
