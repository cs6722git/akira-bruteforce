#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char *argv[])
{
	size_t offset = 0;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
		return 1;
	}
	if (argc > 2) {
		offset = atoi(argv[2]);
	}
	FILE *fp = fopen(argv[1], "rb");
	if (!fp) {
		perror("fopen");
		return 1;
	}
	if (fseek(fp, offset, SEEK_SET) < 0) {
		perror("fseek");
		fclose(fp);
		return 1;
	}
	uint64_t buf;
	fread(&buf, 1, 8, fp);
	printf("0x%016lx\n", buf);
	fclose(fp);
}
