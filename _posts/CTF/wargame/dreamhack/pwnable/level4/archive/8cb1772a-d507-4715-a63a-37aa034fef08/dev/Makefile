SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:src/%.c=obj/%.o)
OBJ_FLAGS = -c -Wall -l pthread -fpack-struct=2 -no-pie -fno-stack-protector -static -s
LINK_FLAGS = -Wall -l pthread -fpack-struct=2 -no-pie -fno-stack-protector -static -s
CC = gcc

bin/dream_restaurant: $(OBJS)
	$(CC) $^ $(LINK_FLAGS) -o $@

obj/%.o: src/%.c
	mkdir -p obj
	$(CC) $< $(OBJ_FLAGS) -o $@

clean:
	rm -r obj bin/dream_restaurant
