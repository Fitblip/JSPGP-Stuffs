# Yay maths

# z == m^d mod n
z  = 0x90e2b728965eda1741eeece031f4ebc543e0b1b847af92e6d1a44017512a3592afbd32307b0207199d8bbcaa9c15a2c96167826526f928ef080475f2d1aee0d4ae0795251023f9be2d9f515dbae460043e4f29f381eea7cec92f7fbf78821fb06bf35a18fe87700f48ecb998a6a6cca9b57689f7529d73d64017103f7da2ffc7

# Public key values
e = 0x010001
n = 0xba806e27852e81f046d939fa9859504c884a628d5e270fc43a54f2d162529a93f07899f38ff7d6f6133316cb0544167c2d67ebdcc542a8812679a00a43068a7b18f41d777503f60ef50bd66eaf0680c401944350cc228bd2c7b11e0d8688f6fd5b5b664c9e716aa1749e7a0eaa787e4d9fcb6702d0d07d2a14c48f597f02f731

# Message digest (SHA256) of our message (Known right)
md1 = 0x0a0a072e30eb31ee65520632e7b361509f91215c1569d477a68fb6e8294b4366

# hlen == hash size length technically -2 for 0x and +1 for off-by-one errors, but combined
# to just be -1 
hlen = (len(hex(md1)) - 1)

h = hex(pow(z,e,n))

print "H = " + str(h)

md2 = h[-hlen:]
md2 = int(md2[:-1],16)

print "MD1 = " + str(hex(md1))
print "MD2 = " + str(hex(md2))


if md1 == md2:
	print "Test passed, yay!"
else:
	print "Test failed, oh nos!"
