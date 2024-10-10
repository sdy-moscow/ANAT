KVER   ?= $(shell uname -r)
KDIR   ?= /lib/modules/$(KVER)/build/
DEPMOD  = /sbin/depmod -a
CC     ?= gcc
obj-m   = xt_ANAT.o
CFLAGS_xt_ANAT.o := -DDEBUG

all: xt_ANAT.ko libxt_ANAT.so

xt_ANAT.ko: xt_ANAT.c
	make -C $(KDIR) M=$(CURDIR) modules CONFIG_DEBUG_INFO=y
	-sync

%_sh.o: libxt_ANAT.c
	gcc -O2 -Wall -Wunused -fPIC -o $@ -c $<

%.so: %_sh.o
	gcc -shared -o $@ $<

sparse: clean | xt_ANAT.c xt_ANAT.h
	make -C $(KDIR) M=$(CURDIR) modules C=1

cppcheck:
	cppcheck -I $(KDIR)/include --enable=all --inconclusive xt_ANAT.c
	cppcheck libxt_ANAT.c

coverity:
	coverity-submit -v

clean:
	make -C $(KDIR) M=$(CURDIR) clean
	-rm -f *.so *_sh.o *.o modules.order

install: | minstall linstall

minstall: | xt_ANAT.ko
	make -C $(KDIR) M=$(CURDIR) modules_install INSTALL_MOD_PATH=$(DESTDIR)

linstall: libxt_ANAT.so
	install -D $< $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/$<

uninstall:
	-rm -f $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/libxt_ANAT.so
	-rm -f $(KDIR)/extra/xt_ANAT.ko

load: all
	-sync
	-modprobe x_tables
	-mkdir -p /lib64/modules/`uname -r`/kernel/net/ipv4/
	-cp xt_ANAT.ko /lib64/modules/`uname -r`/kernel/net/ipv4/
	-depmod `uname -r`
	-modprobe xt_ANAT
	-iptables-restore < iptables.rules
	-conntrack -F
unload:
	-/etc/init.d/iptables restart
	-rmmod xt_ANAT.ko
del:
	-sync
reload: unload clean load

.PHONY: all minstall linstall install uninstall clean cppcheck
