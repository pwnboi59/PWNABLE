CC = gcc
SRC = gym_notes.c 
OUT = gym_notes

build: $(SRC)
	$(CC) -o $(OUT) $(SRC) -fstack-protector-all -Wl,-z,relro,-z,now -fPIE -pie -z noexecstack 

run: build
	./$(OUT)

clean:
	rm -f $(OUT)

.PHONY: build run clean
