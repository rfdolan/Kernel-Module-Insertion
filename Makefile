obj-m := part1/part1.o part2/part2.o 
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	gcc -g -Wall part2/procAncestry.c -o procAncestry

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
