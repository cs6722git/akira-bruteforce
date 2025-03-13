#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PATCH_ADDRESS 0x6DB7

char filename[] = "sample-patched";

int main(int argc, char *argv[]) {

    if (argc > 1) {
        strcpy(filename, argv[1]);
    }

    const char *cmd1 = "clang -O1 -T linker_script.ld -o output.elf main-replacement.c";
    //execute and if it fails, print the error
    if (system(cmd1) != 0) {
        perror("Error compiling main-replacement.c");
        return EXIT_FAILURE;
    }
    //check if dump.bin exists
    if (access("dump.bin", F_OK) != -1) {
        //remove dump.bin
        if (remove("dump.bin") != 0) {
            perror("Error removing dump.bin");
            return EXIT_FAILURE;
        }
    }
    //execute objcopy --dump-section .my_main=dump.bin output.elf
    const char *cmd2 = "objcopy --dump-section .my_main=dump.bin output.elf";
    if (system(cmd2) != 0) {
        perror("Error dumping section .my_main");
        return EXIT_FAILURE;
    }
    //read akira-patched to a buffer
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char *buffer = malloc(size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return EXIT_FAILURE;
    }
    if (fread(buffer, 1, size, file) != size) {
        perror("Error reading file");
        free(buffer);
        fclose(file);
        return EXIT_FAILURE;
    }
    fclose(file);
    //read dump.bin to the buffer + PATCH_ADDRESS
    file = fopen("dump.bin", "rb");
    if (!file) {
        perror("Error opening file");
        free(buffer);
        return EXIT_FAILURE;
    }
    fseek(file, 0, SEEK_END);
    size_t size2 = ftell(file);

    //warn if more than 3 kb
    if (size2 > 3072) {
        printf("WARNING: Section .my_main is larger than 3 KB\n");
    }

    fseek(file, 0, SEEK_SET);
    fread(buffer + PATCH_ADDRESS, 1, size2, file);
    fclose(file);
    //save to our-akira
    file = fopen("our-akira", "wb");
    if (!file) {
        perror("Error opening file");
        free(buffer);
        return EXIT_FAILURE;
    }
    if (fwrite(buffer, 1, size, file) != size) {
        perror("Error writing file");
        free(buffer);
        fclose(file);
        return EXIT_FAILURE;
    }
    fclose(file);
    //set to executable
    const char *cmd3 = "chmod +x our-akira";
    if (system(cmd3) != 0) {
        perror("Error setting executable permission");
        return EXIT_FAILURE;
    }
    free(buffer);
    printf("Patched %s and saved to our-akira\n", filename);

}
