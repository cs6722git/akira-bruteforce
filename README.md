Read more about the akira decryption process at https://tinyhack.com


Initial chacha8 code is from : https://github.com/madMAx43v3r/chia-plotter, the license is Apache 2: https://github.com/madMAx43v3r/chia-plotter/blob/master/LICENSE

Initial kcipher2 code is from https://github.com/l00sy4/LCipher2, the license is GPL v3: https://github.com/l00sy4/LCipher2/blob/main/LICENSE

The License for this software is GPL v3

## Requirements

I tested this on Debian Bookworm, but Ubuntu might be easier to setup

```
apt-get install -y nettle-dev libssl-dev nvidia-cuda-toolkit nvidia-cuda-toolkit-gcc build-essential git nasm
```

## Building

```
git clone https://github.com/yohanes/akira-bruteforce
cd akira-bruteforce
make
```

## Testing

I have provided akira encrypted files (the akira ransomware is patched with my own code to record the timing), you can test it by running

```
cd tests
# Note: this will take several minutes and will make your GPU fans spin fast
./akira-bruteforce run2 config-test.json 
```

Meaning of the fields:

* `count`: number nano seconds tested starting from `start_timestamp`
* `start_timestamp`: the timestamp when the test started
* `brute_force_time_range`: the time range in nano seconds that we are testing (the "offset range")
* `offset`: the start offset of the brute force
* `matches`: the list of matches to check, the `filename` is  used to make the output to be more readable

```json
{
	"count": 20000000,
	"start_timestamp": 1741841294358440000,
	"brute_force_time_range": 30000,
	"offset": 1111000,
	"matches": [
		{
            "filename": "zeroes.vmdk",
			"plaintext": "0x0000000000000000",
			"encrypted": "0xd5b71efb8d6969e5",
			"bitmask": "  0xffffffffffffffff"
		},
		{
            "filename" :"ones.vmdk",
			"plaintext": "0x0101010101010101",
			"encrypted": "0x9d1c37f111077987",
			"bitmask": "  0xffffffffffffffff"
		}		
	]	
}
```

Obtaining plaintext: as explained in the blog post, this depends on the file type

Obtaining ciphertext: use a hex editor, or use the "readhex" in the util directory

```
./util/readhex  tests/ones.vmdk.akira
./util/readhex  tests/ones.vmdk.akira 65535 # for chacha8
```

## chacha8 bruteforce

An example chacha config is like this

```json
{
    "t3_ts": 1741841294374553498,
    "t3_t1_offset": 3000000,
    "t1_t2_start_offset": 1300000,
    "t1_t2_end_offset": 2000000,
    "encrypted": "0x03d3319ddbf9caee",
    "plaintext": "0x0"
}
```

* `t3_ts` is the timestamp found by akira-bruteforce
* `t3_t1_offset` is how far back (maximum) the time from `t1` to `t3`
* `t1_t2_start_offset` is the start offset of the brute force
* `t1_t2_end_offset` is the end offset of the brute force
* `encrypted` is the encrypted value
* `plaintext` is the plaintext value
