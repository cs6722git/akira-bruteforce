#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        perror("Failed to open input file");
        return 1;
    }

    FILE *out = fopen(argv[2], "wb");
    if (!out) {
        perror("Failed to create output file");
        fclose(in);
        return 1;
    }

    // Copy until patch offset
    unsigned char buffer[4096];
    size_t bytes_to_patch = 0x00916f4;
    size_t bytes_read;

    while (bytes_to_patch > 0) {
        size_t chunk = bytes_to_patch < sizeof(buffer) ? bytes_to_patch : sizeof(buffer);
        bytes_read = fread(buffer, 1, chunk, in);
        if (bytes_read != chunk) {
            perror("Failed to read input file");
            goto cleanup;
        }
        if (fwrite(buffer, 1, bytes_read, out) != bytes_read) {
            perror("Failed to write to output file");
            goto cleanup;
        }
        bytes_to_patch -= bytes_read;
    }

    // Write patch bytes
    unsigned char patch[] = {0x31, 0xc0, 0xc3};
    if (fwrite(patch, 1, sizeof(patch), out) != sizeof(patch)) {
        perror("Failed to write patch");
        goto cleanup;
    }

    // Skip original bytes in input
    if (fseek(in, sizeof(patch), SEEK_CUR) != 0) {
        perror("Failed to seek in input file");
        goto cleanup;
    }

    // Copy remaining bytes
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (fwrite(buffer, 1, bytes_read, out) != bytes_read) {
            perror("Failed to write remaining bytes");
            goto cleanup;
        }
    }

    fclose(in);
    fclose(out);
    printf("Successfully created patched file: %s\n", argv[2]);
    return 0;

cleanup:
    fclose(in);
    fclose(out);
    return 1;
}