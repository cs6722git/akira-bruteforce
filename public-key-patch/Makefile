all: patch-public-key read-trailer

patch-public-key: patch-public-key.c
	$(CC) $(CFLAGS) -o $@ $<

read-trailer : read-trailer.c
	$(CC) $(CFLAGS) -Wno-deprecated-declarations -o $@ $< -lcrypto -lhogweed -lnettle

clean:
	rm -f patch-public-key read-trailer