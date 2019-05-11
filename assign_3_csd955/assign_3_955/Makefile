CC = gcc
DBUG = -g
CCFLAGS = -Wall -fPIC -shared

TARGETS = keylogger

all: $(TARGETS)

keylogger: keylogger.c
	$(CC) -o $@ $< 
clean:
	rm -f $(TARGETS)
