CC = gcc
DBUG = -g
CCFLAGS = -Wall -fPIC -shared
LIBSSL = -ldl -lssl -lcrypto

TARGETS = prog myfunctions log


all: $(TARGETS)

prog: prog.c
	$(CC) -o $@ $< 

myfunctions: myfunctions.c
		$(CC) $(CCFLAGS) -o myfunctions.so $< $(LIBSSL)
log: log_taskB.c
	$(CC) -o $@ $<
clean:
	rm -f $(TARGETS)
