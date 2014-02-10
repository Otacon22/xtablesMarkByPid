.PHONY: all clean

obj-m = xt_owner.o

KVERSION = $(shell uname -r)
XTABLES_DIR = $(shell pkg-config --variable=xtlibdir xtables)

all: xt_owner.ko libxt_owner.so

install:
	cp libxt_owner.so $(XTABLES_DIR)/

xt_owner.ko:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

libxt_owner.so: libxt_owner.c
	gcc -fPIC $^ -shared -o $@

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	-test -z libxt_owner.so || rm -f libxt_owner.so
	-test -z libxt_owner.o || rm -f libxt_owner.o
