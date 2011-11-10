"""
// Verification algorithm
  http://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Verifying

// Standard (pg. 21)
  http://csrc.nist.gov/publications/fips/archive/fips186-2/fips186-2.pdf

// Updated Standard
  http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf

// List post about this
  http://www.gossamer-threads.com/lists/gnupg/devel/49814

// FIPS 186-2
  // The signature verification process is as follows: 
      1.) Must satisfy => 0 < r < q && 0 < s < q
      2.) If the two conditions in step 1 are satisfied, the verifier computes the following: 
          w  = s^-1 mod q

          u1 = Hash(m) * w mod q
          u2 = r * w mod q
          v  = ((g^u1*y^u2) mod p) mod q
   
      3.) Sig is valid if v == r

// FIPS 186-3
  // The signature verification process is as follows: 
      1.) The verifier shall check that 0 < r < q and 0 < s < q; 

      2.) If the two conditions in step 1 are satisfied, the verifier computes the following: 
          w  = (s')^-1 mod q. 

          // SHOULD mean that I don't have to truncate...Unless it's DSA-1024
          z = the leftmost min(N, outlen) bits of Hash(M')

          u1 = (zw) mod q
          u2 = ((r')w) mod q
          v  = (((g)^u1 * (y)^u2) mod p) mod q. 

      The string z obtained from Hash(M') shall be converted to an integer. The conversion 
      rule is provided in Appendix C.2. 

      3.) If v = r', then the signature is verified. 
    
    # CRLF added properly this time...
                 = 0xc103ea9a7f23218a014d423fb8e79a0bf808c49e3c0fdfa884097c614d36caaf

    # ...and concatinated with the PGP header! Jebus. (CRC checks out)
                 = 0x97a75a8bf876aa13d0867fe50085343069a1af6e60f3956b044d8dc7efbd888c

================================
"""

def dec2hex(n):
    return "%X" % n

def hex2dec(s):
    return int(s, 16)

# A variation of the extended Euclidian algorithm to
# to supply a modInverse() function. Techincally less
# CPU intensive.
def modInverse(s,q):
    q1 = q
    u, u1 = 1, 0
    v, v1 = 0, 1
    while q:
        p = s // q
        u, u1 = u1, u - p * u1
        s, q = q, s - p * q
    total = u % q1
    return total

# Fermant's little theorm for calculating W
def fermat(s,q):
    total =  pow(s,q-2,q)
    return total


# My sig

r = 0x912315f10cbeb6d1c9f7ca82dd25761edf04bb3188ed041131477ffbef51a289
s = 0x6fc029e7694f2dbbe75f6737750831184eea03b87e7a6ef2f9d2057dc71e3d46

p = 0xbc475b5080f1db157547a1e2481bebf3437b4a5edfe1b689612d6b67cc903be0675c98620f43af8115753d45bf9fe71d0454486acc6c6272adcf6b06fef41b1dfaeee284b8001bef31217ddb358defac61e971ac63b4e22aee8781645e56f8e310b98afea48341164bf25b9a8c99b4fc0e180afbae1df6380d40274df3b1637909d473a3e24f883baed51cbe9952a8fde7bf5678da4cfb406d881a0241a3ca701c861f65541d2a48d15efe1ed5c39d5500bcce474ae36b1e8d5bd9bf2dd4e6d9b645d2ce99183dce7537448ab04ae70f92d1178f70002e474bd3c4b9ccdd98851c73542f20761549b4e83e1fe1bb3fd3bed99ec4ed86e19f25729f530b1f6453
q = 0x962acb37cec223fd1d7661e6a1a4045a97181f9ccce62c2de07d934f383b634d
g = 0x6ddba86c757474d759d95d9aff564417f0bab9d4de4bc907cf00b37f73e3a0ecd0a069b4fe270c5a765488bac85395bc36fa32fb7190730ab497b6979b18e839414422c9e61328c6f9d05e6aad0f1891d539a1d38874ca031e702a49280aad500164295c41bdf6566ee0d166c9366e4614672c87eb6084058c894bf3d800957b3e5ed3a284c628e953fbd470f6a3847344647fe4e018ee6602707656696f4032823f2381644ae96758f493ce02342ef005ef64e9b58fcc3866fca0489f59e635c6e59e418dc173ee6bdad6eaee5eacd8919f0334a5690e61b2bc0df32a179559faf2132069960d2be0bd496c2ce6ad5ce9d9d6db2064ddfbfc3bf8acf0a3e492
y = 0x4a239ed8fead4b7b22a7950eed67808355e63f6f5983b2c74f5aec4924f759f51cf058bd0688abbc38246a21d13dd58cb7dd0f538f610befe730e5193561d49d6547981c725a4528d541c1080eb716ef93216c0b3c1196e41c2c01696532ed4bac74e5deef9b29144ed42c26feb52592ec9e492838daf021b87b1802cb95d36f7b1e9eaae65f3921d2499fdad1b272f1dc746611129a1904a7f5ab2c72e3bd0fe14a3b7beb4b53550d9b11fdf9cd35dd4e46f70c0f4d6fb24ee305c60e297d805dc3a4ba53867c49e82259c081c05006d6a9c1f1687713bb1ab9bcc16cfec75faefbcc3e3b8ce13cc5dbb9ad379a16071c8a3677fc3838e12143fad06158263f

m = 0x97a75a8bf876aa13d0867fe50085343069a1af6e60f3956b044d8dc7efbd888c

"""
# Spec sig
r = 0x8bac1ab66410435cb7181f95b16ab97c92b341c0
s = 0x41e2345f1f56df2458f426d155b4ba2db6dcd8c8
p = 0x8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291
q = 0xc773218c737ec8ee993b4f2ded30f48edace915f
g = 0x626d027839ea0a13413163a55b4cb500299d5522956cefcb3bff10f399ce2c2e71cb9de5fa24babf58e5b79521925c9cc42e9f6f464b088cc572af53e6d78802
y = 0x19131871d75b1612a819f29d78d1b0d7346f7aa77bb62a859bfd6c5675da9d212d3a36ef1672ef660b8c7c255cc0ec74858fba33f44c06699630a76b030ee333

m = 0xa9993e364706816aba3e25717850c26c9cd0d89d

# w  = 0x9df4ece5826be95fed406d41b43edc0b1c18841b
# u1 = 0xbf655bd046f0b35ec791b004804afcbb8ef7d69d
# u2 = 0x821a926312e97adeabcc8d082b5278978a2df4b0

# v  = 0x8bac1ab66410435cb7181f95b16ab97c92b341c0 \
#                                                  |=> Match as they're supposed to
# r  = 0x8bac1ab66410435cb7181f95b16ab97c92b341c0 /
"""

try:
    r
except:
    print "You need to uncoment a set of values!"
    exit(1)

if 0 < r < q and 0 < s < q:
    print "Valid sig"
else:
    print "Invalid sig!"
    exit(1)

w  = modInverse(s,q)  
print "W = " + str(hex(w))

u1 = (m * w) % q
print "U1 = " + str(hex(u1))

u2 = (r * w) % q
print "U2 = " + str(hex(u2))

v  = (((pow(g, u1, p) * pow(y, u2, p))) % p ) % q
print "R = " + str(hex(r))
print "V = " + str(hex(v))

if r == v:
	print "Test passed, yay!"
else:
	print "Test failed, oh nos!"
