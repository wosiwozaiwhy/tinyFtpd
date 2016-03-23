.PHONY:clean
CC = gcc
CFLAGS = -Wall -g 
BIN = tinyFtpd
OBJS = main.o sysutil.o session.o ftpproto.o nobody.o str.o tunable.o parseconf.o
LIBS=-lcrypt
$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
%.o:%.c
	$(CC) $(CFLAGS)  -c $< -o $@
clean:
	rm -f *.o $(BIN)