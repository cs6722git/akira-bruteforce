#generate test files
with open("tests/zeroes.vmdk", "wb") as f:
    f.write(b'\x00' * (5*1024*1024))            
with open("tests/ones.vmdk", "wb") as f:
    f.write(b'\x01' * (5*1024*1024))

