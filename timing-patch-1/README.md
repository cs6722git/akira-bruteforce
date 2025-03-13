This is an attempt to measure how fast is the random key/IV generation

I assume you already have patched sample as explained in ../public-key-patch

This is done by overwriting the main function with our code, that will call the `generate_random`

This is not very accurate (too fast, it doesn't get interupted), but we can get the lower bound for our offset

How to use:
```
cp ../sample-akira .
make
./patch-code
./our-akira
```
