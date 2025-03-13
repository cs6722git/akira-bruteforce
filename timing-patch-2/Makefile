all: patch1.bin patch2.bin patch3.bin patch4.bin patcher read-log 

patcher: patcher.c
	$(CC) $(CFLAGS) -o $@ $< 

read-log: read-log.c
	$(CC) $(CFLAGS) -o $@ $< -lnettle


patch1.bin: patch1.asm
	nasm -f bin -o $@ $<
patch2.bin: patch2.asm
	nasm -f bin -o $@ $<
patch3.bin: patch3.asm
	nasm -f bin -o $@ $<	
patch4.bin: patch4.asm
	nasm -f bin -o $@ $<		
clean:
	rm -f patch1.bin patch2.bin patch3.bin patch4.bin patcher read-log 
