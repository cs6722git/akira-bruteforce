# Patch to record timing

I assume that you already have patched akira sample, as explained in ../public-key-patch

To get an accurate reading of the time taken to generate a random key/IV, we will need to record the ransomware encrypting real files.

These patches will record the time taken to encrypt a file, and write it to a file named `/tmp/log.bin`

Since this is multithreaded, we don't know the order of the log, but we can figure it out later by reading the trailer of the files, and matching the timestamp.

## patch1.asm

This is added after getting the current time, we record it in the heap.

### patch2.asm

This is a function that will write the content of the heap (containing list of timestamp) into a file named `/tmp/log.bin`

### patch3.asm

This will write the log everytime a new file is processed (this will call `patch2.asm`)

### patch4.asm

This is the initial function that will allocate a buffer using `malloc`

## How to use:

```
cp ../sample-akira .
make
./patch-code sample-patched akira-ts
#copy akira-ts on ESXI host
scp akira-ts esxi-host:
#use akira-ts on ESXI host
./akira-ts -n=15 -p=/vmfs/volumes/testdir/
#pull /tmp/log.bin
./read-log log.bin
#to dump the keys for a file
../public-key-patch/read-trailer filename.vmdk.akira log.bin
```

