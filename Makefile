# let's assume the module C file is named latprof.c
obj-m := latprof.o

CONFIG_MODULE_SIG=n
#KDIR := /lib/modules/$(shell uname -r)/build
KDIR := ../linux

PWD := $(shell pwd)

all: latprof.c
	make -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	make -C $(KDIR) SUBDIRS=$(PWD) clean

#$()
