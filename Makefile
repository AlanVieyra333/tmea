PROJ = TMEA
CC = gcc
OBJS = lib/aes.o lib/gcm.o lib/utils.o lib/aes-intrinsics.o lib/gcm-intrinsics.o lib/utils-intrinsics.o lib/tmea_tree.o
DEPS = include/aes.h include/gcm.h include/utils.h include/aes-intrinsics.h include/gcm-intrinsics.h include/utils-intrinsics.h include/tmea_tree.h
CFLAGS = -c -Iinclude -O3
LFLAGS = -Iinclude -O3
LIBS = -maes -mavx -mpclmul -msha

all: $(PROJ)

$(PROJ): main.c $(OBJS)
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)
	@echo "Compilado correctamente."

$(OBJS): %.o: %.c $(DEPS)
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

run: $(PROJ)
	./$(PROJ)

clean:
	rm -rf *.o **/*.o *.a $(PROJ)

test:
	openssl aes-128-cbc -in test/in.dat -out test/out.dat -K 31323334353637383930313233343536 -iv 00000000000000000000000000000000

.PHONY: all run clean test
