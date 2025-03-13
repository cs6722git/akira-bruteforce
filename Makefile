all: akira-bruteforce decrypt

akira-bruteforce: akira-bruteforce.cu chacha8.c
	nvcc  --compiler-options -Wall -arch=sm_86  $(CFLAGS) -O3 -o $@ $^ 

decrypt: decrypt.c chacha8.c kcipher2.c
	$(CC) $(CFLAGS) -static -o $@ $^ -lnettle -lhogweed	
