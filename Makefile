CC=gcc
AR=ar
CFLAGS=-Wall
LDFLAGS=-L ./libgf256
LDLIBS=-lgf256
INC=-I ./libgf256
EXEC=aestest
LIB=libaes.a
SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
TESTSUITE_SOURCE := aes_test.c
LIB_SRC=$(filter-out $(TESTSUITE_SOURCE),$(wildcard *.c))
LIB_OBJ=$(LIB_SRC:.c=.o)

all : $(EXEC) $(LIB)

$(EXEC) : $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(LIB): $(LIB_OBJ)
	$(AR) rcs $(LIB) $(LIB_OBJ)

aes.o : aes.h

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(INC)


clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)
	rm -rf ${LIB}	