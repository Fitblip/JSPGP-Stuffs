/* OpenPGP public key extraction
 * Copyright 2005 Herbert Hanewinkel, www.haneWIN.de
 * version 1.1, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other materials
 * provided with the application or distribution.

====================================================================================

 * Heavily modified, but using some algorithms from the original
 * so citing him just to be on the safe side...

 * Ryan Sears
 * Oct, 2011

Other resources used:
http://www.iana.org/assignments/pgp-parameters/pgp-parameters.xml
http://tools.ietf.org/html/rfc4880
http://www.rfc-ref.org/RFC-TEXTS/2440/chapter5.html

*/

/* 
    # Full breakdown of signature packet    
     === Packet Header ===
   $ 4      // Version Number
   $ 19     // Sig type (0x13)
   $ 17     // pub key algo
   $ 8      // digest algo
   $ 0      // count1
   $ 40     // count2 => Hashed subpacket == 40 bytes
       # 5      // Subpacket Count
        + 2     // Signature Creation Time (Scalar rep)
         = 78   // Date1
         = 177  // Date2
         = 148  // Date3
         = 174  // Date4

       # 2      // Subpacket Count
        + 27    // Key flags (packet 27)
         = 3    // Flag 03 => 0x01 + 0x02 => can be used to sign and certify other keys

       # 5      // Subpacket Count
        + 9     // Key Expiration Time (Scalar rep)
         = 0    // Sec1
         = 13   // Sec2
         = 47   // Sec3
         = 0    // Sec4

       # 6      // Subpacket Count
        + 11    // Preferred Symmetric Algorithms
         = 9    // AES with 256-bit key
         = 8    // AES with 192-bit key
         = 7    // AES with 128-bit key
         = 3    // CAST5 (128 bit key, as per RFC 2144)
         = 2    // TripleDES (DES-EDE, [SCHNEIER] [HAC] 168 bitkey derived from 192)

       # 6      // Subpacket Count 
        + 21    // Preferred Hash Algorithms
         = 8    // SHA256
         = 2    // SHA-1
         = 9    // SHA384
         = 10   // SHA512
         = 11   // SHA224

       # 4      // Subpacket Count 
        + 22    // Preferred Compression Algorithms
         = 2    // ZLIB
         = 3    // BZip2
         = 1    // ZIP

       # 2      // Subpacket Count 
        + 30    // Features
         = 1    // Modification Detection

       # 2      // Subpacket Count 
        + 23    // Key Server Preferences
         = 128  // No-modify (0x80)

   $ 0      // count1
   $ 10     // count2 => Unhashed subpacket == 10 bytes

       # 9      // Subpacket Count 
        + 16    // Key Server Preferences
         = 9    // 0x09
         = 207  // 0xCF
         = 190  // 0xBE
         = 215  // 0xD7
         = 221  // 0xDD
         = 32   // 0x20
         = 153  // 0x99
         = 240  // 0xF0
            \->  09CFBED7DD2099F0
*/    


debug = false

// Converts string => Hex
function toHex(str) {
    var hex = '';
    for(var i=0;i<str.length;i++) {
        hex += ''+str.charCodeAt(i).toString(16);
    }
    return hex;
}

function dec2hex(d) {
    var hex = Number(d).toString(16);
    padding = 2
    while (hex.length < padding) {
        hex = "0" + hex;
    }
    return hex;
}


function publicKey(key) {
    // Check for header thing
    if (key.indexOf('-----BEGIN PGP PUBLIC KEY BLOCK-----') != -1 ) {
        if (debug) {console.log('Key Found');}
    } else {
        if (debug) {console.log('No key found');}
        this.err = "No public key supplied!";
        return;
    }

    // Check for last tidbit, plus ending thing, and make sure they're in the right order.
    if (key.indexOf('\n=') != -1 && key.indexOf('\n') != -1 && key.indexOf('\n=') < key.indexOf('\n-----END PGP PUBLIC KEY BLOCK-----')) {
        if (debug) {console.log('Valid key');}
    } else {
        if (debug) {console.log('Invalid key');}
        this.err = "Invalid Key!";
        return;
    }

    // Compensate for the two \n chars and find our finish
    start = key.indexOf('\n\n') + 2;
    finish = key.indexOf('=\n');

    if ((finish - start) < 20) {
        this.err = "Truncated key?"
        return;
    }

    // Slice our key out
    key = key.slice(start,finish);
    if (debug) console.log("Key start:finish => " + start + ":" + finish + "\n" + key);

    // Base64 decode our key 
    decoded = r2s(key);
    if (debug) console.log("\nBase64 decoded;\n" +decoded);

    for (i=0; i < decoded.length;){

        // Loop over our base64 decoded key, and do byte-by-byte analysis
        var a = decoded.charCodeAt(i++);

        // If (byte AND 128) == 0, then break loop
        if ((a & 128) == 0) break; 

        // This massages our bytes so we can parse them properly later. Jebus.
        // If (byte AND 64) == 0 
        if (a & 64) {
            a &= 63;
            // Next byte in header is length of packet
            var len=decoded.charCodeAt(i++);
            // If our length is between 192 and 223
            if(len > 191 && len < 224) {
                // Shift left 8 bits and add to our next byte
                len=((len-192)<<8) + decoded.charCodeAt(i++);
            // Or if our length is between 224 and 255
            } else if(len>223 &&len<255) {
                // Shift 1 left len AND 31 bits over
                len = (1<<(len&31)); 
            }
            // Or if our length is 255
            } else if (len==255) {
                // Shift the next 3 bytes 24, 16, and 8 bits accordingly, sum them with the 4th bit
                len = (decoded.charCodeAt(i++)<<24) + (decoded.charCodeAt(i++)<<16) + (decoded.charCodeAt(i++)<<8) + decoded.charCodeAt(i++);
        // If (byte AND 64) == 0 
        } else {
            // len = (byte AND 3)
            len = a&3;
            // byte = (byte shifted 2 right) AND 15
            a = (a>>2)&15;
            // if len is 0
            if(len==0) {
                // New len is next byte
                len = decoded.charCodeAt(i++);
            // if len is 1
            } else if(len==1) {
                // shift next bit left 8 and add to byte after that
                len = (decoded.charCodeAt(i++)<<8) + decoded.charCodeAt(i++);
            // if len is 2
            } else if(len==2) { 
                // shift next 3 bits left 24, 16, and 8 respectively and sum with 4th bit
                len = (decoded.charCodeAt(i++)<<24) + (decoded.charCodeAt(i++)<<16) + (decoded.charCodeAt(i++)<<8) + decoded.charCodeAt(i++);
            // if len > 2
            } else {
                // len == last byte
                len = decoded.length-1;
            }
        }

        // 6 == public key packet
        // 14 == subkey packet
        if(a==6 || a==14) {

            // k = starting byte
            var k = i;

            // vers == next byte
            var vers=decoded.charCodeAt(i++);

            // Set version to be returned
            this.vers = vers;

            // Timestamp of creation
            var time = (decoded.charCodeAt(i++)<<24) + (decoded.charCodeAt(i++)<<16) + (decoded.charCodeAt(i++)<<8) + decoded.charCodeAt(i++);

            // Epoch => date conversion and localization
            time = time * 1000;
            date = new Date(time)
            this.created = date.toLocaleString();


            // If valid == 0, valid key was found (Older keys only)
            if(vers==2 || vers==3) {
                var valid=decoded.charCodeAt(i++)<<8 + decoded.charCodeAt(i++);
            }

            // This packet is our algorithm packet
            var algo = decoded.charCodeAt(i++);

            // 1 == RSA (Encrypt or Sign)
            // 2 == RSA (Encrypt only)
            if(algo == 1 || algo == 2) {
                var m = i;
                var lm = Math.floor((decoded.charCodeAt(i)*256 + decoded.charCodeAt(i+1)+7)/8);
                i+=lm+2;

                var mod = decoded.substr(m,lm+2);
                var le = Math.floor((decoded.charCodeAt(i)*256 + decoded.charCodeAt(i+1)+7)/8);
                i+=le+2;

                this.pkey=s2r(decoded.substr(m,lm+le+4));
                this.type="RSA";

                if(vers==3) {
                    this.fp='';
                    this.keyid=toHex(mod.substr(mod.length-8, 8));
                } else if(vers==4) {
                    var pkt = String.fromCharCode(0x99) + String.fromCharCode(len>>8) + String.fromCharCode(len&255)+decoded.substr(k, len);
                    var fp = SHA1(pkt);
                    this.fp=toHex(fp);
                    this.keyid=toHex(fp.substr(fp.length-8,8));
                } else {
                    this.fp='';
                    this.keyid='';
                }
            // 16 == ElGamel
            // 20 == Reserved (Formally Elgaml Encrypt or Sign)
            // Version 4
            } else if ((algo == 16 || algo == 20) && vers == 4) {

                // Set up primes to parse out
                primes = ['p','g','y'];
                // Set up new dictionary to store each hex representation
                a = {};
                a['p'] = "";
                a['g'] = "";
                a['y'] = "";
                i -= 1

                for (c=0;c<primes.length;c++){
                    size = Math.floor((decoded.charCodeAt(++i) * 256 + decoded.charCodeAt(i + 1) + 7) / 8)   
                    for (b=0;b<size;b++) {
                        a[primes[c]] += String(dec2hex(decoded.charCodeAt(i + b + 2)));
                    }
                    a[primes[c]] = a[primes[c]].split(' ')
                    i += (size +1)
                }

                this.elgamelP = new BigInteger(a['p'].toString(),16)
                this.elgamelG = new BigInteger(a['g'].toString(),16)
                this.elgamelY = new BigInteger(a['y'].toString(),16)

                var pkt = String.fromCharCode(0x99) + String.fromCharCode(len >> 8) + String.fromCharCode(len & 255) + decoded.substr(k, len);
                var fp = SHA1(pkt);
                this.fp = toHex(fp); 
                this.keyid = toHex(fp.substr(fp.length - 8, 8));
                this.type = "ELGAMAL";
                found = 3;

            // We found the DSA sig stuffs
            } else if (algo == 17 && vers == 4) {
                var m = i;
                primes = ['p','q','g','y'];
                a = {};
                a['p'] = "";
                a['q'] = "";
                a['g'] = "";
                a['y'] = "";

                i -= 1
                for (c=0;c<primes.length;c++){
                    // Nice workaround for the rounding problem. Ugly problem. 
                    size = Math.floor((decoded.charCodeAt(++i) * 256 + decoded.charCodeAt(i + 1) + 7) / 8)   
                    for (b=0;b<size;b++) {
                        a[primes[c]] += String(dec2hex(decoded.charCodeAt(i + b + 2)));
                    }
                    a[primes[c]] = a[primes[c]].split(' ')
                    i += (size +1)
                }
                
                this.dsaP = new BigInteger(a['p'].toString(),16)
                this.dsaQ = new BigInteger(a['q'].toString(),16)
                this.dsaG = new BigInteger(a['g'].toString(),16)
                this.dsaY = new BigInteger(a['y'].toString(),16)

                // Line up damn it!
                i += 1

            } else {
                i = k + len;
            }
        // If we have a UserID packet
        } else if (a == 13) {
            // Parse out UTF-8 string of info
            this.user = decoded.substr(i, len);
            i += len;

        // If we have a signature packet for a version 4 key
        } else if (a == 2 && vers == 4) {
            // Record initial packet            
            var p = i;

            // Skip our header info
            i = i + 4;

            // Hashed packet count
            hCount = ((decoded.charCodeAt(i++)<<8) + decoded.charCodeAt(i++));

            // For each hashed packet
            max = i + hCount;
            ar = new Array();
            while (i < max) {
                ar = [];
                // Make an array of subpacket info
                for (c=0;c<decoded.charCodeAt(i);c++) {
                    ar.push(decoded.charCodeAt(i + c + 1));
                }

                // If we found the expiration subpacket
                if (ar[0] == 9) {

                    // Remove packet type
                    ar.shift();
                    // Bit-shift & scalar magic to get expiration seconds 
                    for (t=0;t<ar.length;) {
                        var exp = ((ar[t++]<<24) + (ar[t++]<<16) + (ar[t++]<<8) + ar[t++]) * 1000;
                    } 
                    // Calculate the expiration date
                    exp = time + exp;
                    expdate = new Date(exp);
                    this.exp = expdate.toLocaleString();

                // If we found preferred hashing algo packet
                } else if (ar[0] == 21) {

                    // List of known supported hashing algorithms
                    algos = new Object();
                    algos[1] = "MD5";
                    algos[2] = "SHA-1";
                    algos[3] = "RIPE-MD/160";
                    algos[8] = "SHA-256";
                    algos[9] = "SHA384";
                    algos[10] = "SHA512";
                    algos[11] = "SHA224";

                    // Remove packet type
                    ar.shift();
                    this.hash = algos[ar[0]];
                }
                // Count up packet lengths
                i += decoded.charCodeAt(i) + 1;
            }

            // If we can't find either of these, just set them to a dummy value
            if (this.exp == null) {
                this.exp = "Never";
            }
            if (this.hash == null) {
                this.hash = "Unknown";
            }
    
            // Revert to original i value, and increment fixed packet length
            i = p;
            i += len;

        } else {
            i += len;
        }
    }  
}


