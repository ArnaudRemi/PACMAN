#replace CFLAGS by FOOCFLAGS -> remi arnaud

FOOCFLAGS = -fomit-frame-pointer -D_GNU_SOURCE -g -Wall
FOOCFLAGS_ARM = -fomit-frame-pointer -D_GNU_SOURCE -DARM -Wall
CC = gcc
CC_ARM = arm-linux-gcc

KERNEL = $(shell uname -r)
KINC =  $(shell $(CC) -print-search-dirs | sed -ne 's/install: \(.*\)/-I\1include/gp') -I/lib/modules/$(KERNEL)/build/include

KINC_ARM = -I/tm/proj/iponair/newdemo/2.4.18-rmk3-hh21/linux/kernel/include
#KINC_ARM = -I/tm/proj/iponair/newdemo/2.4.19-rmk6-pxa1-hh36.11/linux/kernel/include

KDIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)

KFOOCFLAGS = -O2 -fomit-frame-pointer -Wall $(KINC) 
KFOOCFLAGS_ARM = -O2 -fomit-frame-pointer -DARM -Wall $(KINC_ARM) 

SRC = main.c packet_input.c olsr_d3.c olsr.c libipq.c table.c list.c pdad_algo.c \
	addr_mgr.c fsr.c # mcast.c

OBJS =  $(SRC:%.c=%.o)
OBJS_ARM =  $(SRC:%.c=%-arm.o)

obj-m := kpacman.o
EXTRA_FOOCFLAGS += -I/lib/modules/$(KERNEL)/build/include/asm-i386/mach-default

default: etags pacman

all: default

tools: testolsr timediff stat_client
arm: pacman-arm kpacman-arm.o

arm-install:
	for i in 1 2 3 4 5 6; do scp pacman ipaq$$i:pdad/; done

etags:
	find . -name '*.[ch]' -print | etags -

$(OBJS): %.o: %.c Makefile
	$(CC) $(FOOCFLAGS) -c -o $@ $<

$(OBJS_ARM): %-arm.o: %.c Makefile
	$(CC_ARM) $(FOOCFLAGS_ARM) -c -o $@ $<

pacman: $(OBJS) Makefile
	#$(CC) $(FOOCFLAGS) -lm -o $@ $(OBJS)
	$(CC) $(FOOCFLAGS) -o $@ $(OBJS) -lm

pacman-arm: $(OBJS_ARM) Makefile
	#$(CC_ARM) $(FOOCFLAGS_ARM) -lm -o $(@:%-arm=%) $(OBJS_ARM)
	$(CC_ARM) $(FOOCFLAGS_ARM) -o $(@:%-arm=%) $(OBJS_ARM) -lm

kpacman.o: kpacman.c
	$(CC) $(KFOOCFLAGS) -c -o $@ $<

kpacman.ko: kpacman.c
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

kpacman-arm.o: kpacman.c
	$(CC_ARM) $(KFOOCFLAGS_ARM) -c -o $(@:%-arm.o=%.o) $<

testolsr: test/tools/testolsr.c Makefile
	$(CC) $(FOOCFLAGS) -o test/tools/$@ test/tools/testolsr.c

timediff: test/tools/timediff.c Makefile
	$(CC) $(FOOCFLAGS) -o test/tools/$@ test/tools/timediff.c

stat_client: test/toolsstat_client.c Makefile
	$(CC) $(FOOCFLAGS) -o test/tools/$@ test/tools/stat_client.c

depend:
	@echo "Updating Makefile dependencies..."
	@makedepend -Y./ -- $(DEFS) -- $(SRC) &>/dev/null

clean: 
	rm -f pacman *~ *.o kpacman.ko core test/tools/testolsr test/tools/timediff test/tools/stat_client 

# DO NOT DELETE

main.o: libipq.h list.h table.h pacman.h olsr_d3.h olsr.h fsr.h
main.o: packet_input.h addr_mgr.h pdad_algo.h
packet_input.o: libipq.h list.h table.h pacman.h packet_input.h pdad_algo.h
packet_input.o: addr_mgr.h
olsr_d3.o: list.h table.h olsr_d3.h pacman.h pdad_algo.h
olsr.o: list.h table.h olsr.h pacman.h pdad_algo.h
libipq.o: libipq.h
table.o: list.h table.h pacman.h
list.o: list.h
pdad_algo.o: list.h table.h pacman.h pdad_algo.h addr_mgr.h
addr_mgr.o: list.h table.h pacman.h pdad_algo.h addr_mgr.h
fsr.o: list.h table.h fsr.h pacman.h pdad_algo.h
