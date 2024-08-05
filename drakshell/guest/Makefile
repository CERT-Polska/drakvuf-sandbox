IDIR =./include
CFLAGS=-I$(IDIR) -fPIE -nostdlib -ffreestanding -masm=intel -march=haswell -fshort-wchar -O2
LFLAGS=-T linker.ld
ODIR=obj

_DEPS = nt_loader.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = nt_loader.o drakshell.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

drakshell: $(ODIR)/drakshell.elf
	objcopy -O binary -j.text -j.bss --set-section-flags .bss=alloc,load,contents $^ drakshell

$(ODIR)/%.o: %.c $(DEPS)
	gcc -c -o $@ $< $(CFLAGS)

$(ODIR)/drakshell.elf: $(OBJ)
	gcc $(LFLAGS) -o $@ $^ $(CFLAGS)

clean:
	rm -f drakshell $(ODIR)/*.o $(ODIR)/*.elf *~ core $(INCDIR)/*~

.PHONY: clean
