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

debug = false

function dec2hex(d) {
    var hex = Number(d).toString(16);
    padding = 2
    while (hex.length < padding) {
        hex = "0" + hex;
    }
    return hex;
}

// Parses out our email text properly into a format primed for hashing
function parseText() {
    var stuffs = document.getElementsByName('message')[0].value

    // Split everything on newlines into an array
    stuffs = stuffs.split('\n')

    // Find our hashing algorithm
    for (i=0;i<stuffs.length;i++) {
        if ( stuffs[i].search(/^Hash.*$/) != -1) {
            start = i
        }
    }

    // Grab our hashing algorithm
    this.hash = stuffs[start].split(" ").pop()
    // Start the line after our hashing algo, where text is
    start = start + 2 
    end = stuffs.indexOf('-----BEGIN PGP SIGNATURE-----')

    // Loops through our lines array, if it is blank, stick in 
    // our \r\n\r\n sequence. Makes it more fault tolerant for 
    // windows/linux/unix in theory. 
    this.msg = '';
    for (i=start;i<end;i++) {
        // Replace all \r and \n chars, and strip off ending spaces
        // Originally used trim(), but it would get rid of ALL spaces :(
        if (stuffs[i].replace('\r','').replace('\n','').replace(/\s+$/,'') == "") {
            stuffs[i] = '\r\n'
            this.msg += stuffs[i]
        } else {
            // Don't pad last line with \r\n chars
            if (i == end -1 ) {
                this.msg += stuffs[i].replace(/\s+$/,'').replace('\r','').replace('\n','')
            } else {
                this.msg += stuffs[i].replace(/\s+$/,'').replace('\r','').replace('\n','') + '\r\n'
            }
        }
    }
}

// Parse out the signature part of our message for concatination with our msg text
function parseSig() {
    var stuffs = document.getElementsByName('message')[0].value;
    stuffs = stuffs.replace(/^Version.*\n$/m, '');
    start  = stuffs.indexOf('-----BEGIN PGP SIGNATURE-----\n\n') + 31;
    end    = stuffs.search(/\n=.*\n-----END PGP SIGNATURE-----$/);
    sig = stuffs.slice(start,end);
    var sigdecoded = r2s(sig);

    for (i=0;i<sigdecoded.length;i++) {
        // Poor mans skip of the first 2-3 bytes
        if (dec2hex(sigdecoded.charCodeAt(i)) == '04') {
            // Packet stuffs
            version = dec2hex(sigdecoded.charCodeAt(i++))
            sigtype = dec2hex(sigdecoded.charCodeAt(i++))
            pubalg  = dec2hex(sigdecoded.charCodeAt(i++))
            hashalg = dec2hex(sigdecoded.charCodeAt(i++))
            size1   = sigdecoded.charCodeAt(i++)
            size2   = sigdecoded.charCodeAt(i++)

            // Figure out how big everything is
            sizetotal = ((size1<<8) + (size2)) 

            // Loop over any hashed bytes and push each packet type into
            // an array
            var ar = new Array();
            for (b=0;b<sizetotal;b++) {
                psize   = dec2hex(sigdecoded.charCodeAt(i++))
                ar.push(psize)
                for (c=0;c<psize;c++) {
                    ar.push(dec2hex(sigdecoded.charCodeAt(i++)));
                    b++
                }
            }

            // Update for previous bytes
            sizetotal += 6

            // Pad bytes properly
            if (sizetotal < 255) {
                sizetotal = '000000' + String(dec2hex(sizetotal));
            } else if (sizetotal > 256 && sizetotal < 65534) {
                a = '0000' + String(dec2hex(sizetotal));
            } else if (sizetotal > 65535 && sizetotal < 16777215) {
                a = '00' + String(dec2hex(sizetotal));
            } else if (sizetotal > 16777216) {
                a = String(dec2hex(sizetotal));
            }

            // Add all hashed bytes to a long string, and parse properly
            hpacket = ''    
            for (d=0;d<ar.length;d++) {
                hpacket += String.fromCharCode(parseInt(ar[d],16))
            }

            // Build our header string to be thrown into SHA256()
            // Also BWAHAHA I ARE MIGHTIER THEN THE HASHING ALGORITHM!
            this.header = String.fromCharCode(parseInt(version,16)) +
                     String.fromCharCode(parseInt(sigtype,16)) +
                     String.fromCharCode(parseInt(pubalg,16)) +
                     String.fromCharCode(parseInt(hashalg,16)) +
                     String.fromCharCode(parseInt(dec2hex(size1),16)) +
                     String.fromCharCode(parseInt(dec2hex(size2),16)) +
                     hpacket + 
                     // I belive these are static values for v4 keys
                     String.fromCharCode(parseInt('04',16)) +
                     String.fromCharCode(parseInt('ff',16)) +
                     // Last 4 bytes are the size of the entire header
                     String.fromCharCode(parseInt(sizetotal.substr(0,2),16)) +
                     String.fromCharCode(parseInt(sizetotal.substr(2,2),16)) +
                     String.fromCharCode(parseInt(sizetotal.substr(4,2),16)) +
                     String.fromCharCode(parseInt(sizetotal.substr(6,2),16))

            // Calculate our unhashed total packet size, and skip it
            // Usually a key id, maybe other info we shouldn't really trust. Big freaking deal.
            size1 = sigdecoded.charCodeAt(i++)
            size2 = sigdecoded.charCodeAt(i++)
            sizetotal = ((size1<<8) + (size2)) 
            i += sizetotal

            // CRC values (left-most 2 bytes of the hash)
            CRC1 = dec2hex(sigdecoded.charCodeAt(i++));
            CRC2 = dec2hex(sigdecoded.charCodeAt(i++));
            this.CRC = CRC1 + CRC2;
            (debug) && console.log('CRC => ' + CRC)

            if (info.type == "DSA") {
                primes = ['r','s'];
                a = {};
                a['r'] = "";
                a['s'] = "";
                i -= 1
                for (c=0;c<primes.length;c++){
                    size = Math.floor((sigdecoded.charCodeAt(++i) * 256 + sigdecoded.charCodeAt(i + 1) + 7) / 8) 
                    for (b=0;b<size;b++) {
                        a[primes[c]] += String(dec2hex(sigdecoded.charCodeAt(i + b + 2)));
                    }
                    a[primes[c]] = a[primes[c]].split(' ')
                    i += (size +1)
                }
                this.dsaR = new BigInteger(a['r'].toString(),16)
                this.dsaS = new BigInteger(a['s'].toString(),16)
            } else if (info.type == "RSA") {
                a = {};
                a['z'] = ""
                i -= 1
                size = Math.floor((sigdecoded.charCodeAt(++i) * 256 + sigdecoded.charCodeAt(i + 1) + 7) / 8)   
                for (b=0;b<size;b++) {
                    a['z'] += String(dec2hex(sigdecoded.charCodeAt(i + b + 2)));
                }
                a['z'] = a['z'].split(' ')
                i += (size +1) 
                this.rsaZ = new BigInteger(a['z'].toString(),16)
            } else {
                //error
            }
            // Break after we get the info we need
            break
        }
    }
}

// MAAAAAAAATH 
function RSAVerify(z,e,n,hash){
    var hash = new BigInteger(hash,16)
    var mdtmp = z.modPow(e,n)
    var mdtmp = new BigInteger(mdtmp.toString(16).substr(mdtmp.toString(16).length-64,mdtmp.toString(16).length),16)    

    if (mdtmp.compareTo(hash) == 0) {
        return true
    } else {
        return false
    }
}

// MOAR MAAAAAAAAAAATH
function DSAVerify(g,p,q,y,r,s,hash) {
    // If our DSA key is < 1535 (2048), then truncate
    // the sha256 hash value to 40 bytes
    if (p.toString(16).length < 512) {
        hash = hash.substr(0,40)
    }

    // Calculate individual pieces
    m = new BigInteger(hash,16);
    w = s.modInverse(q);
    u1 = m.multiply(w).mod(q);
    u2 = r.multiply(w).mod(q);

    // Steps to calculate v
    a = g.modPow(u1,p);
    b = y.modPow(u2,p);
    c = a.multiply(b).mod(p)
    v = c.mod(q)

    // If v == r
    if (v.compareTo(r) == 0) {
        return true
    } else {
        return false
    }
}

function publicKey(key) {
    // Check for header thing
    if (key.indexOf('-----BEGIN PGP PUBLIC KEY BLOCK-----') != -1 ) {
        (debug) && console.log('Key Found');
    } else {
        (debug) && console.log('No key found');
        this.err = "No public key supplied!";
        return;
    }

    // Check for last tidbit, plus ending thing, and make sure they're in the right order.
    if (key.indexOf('\n=') != -1 && key.indexOf('\n') != -1 && key.indexOf('\n=') < key.indexOf('\n-----END PGP PUBLIC KEY BLOCK-----')) {
        (debug) && console.log('Valid key');
    } else {
        (debug) && console.log('Invalid key');
        this.err = "Invalid Key!";
        return;
    }

    // Make this a lot more fault tolarent
    // Search and replace for Version:blahblahblah, and remove
    // Then verify that we chmop everything between start and end
    key = key.replace(/^Version.*\n$/m, '')
    start = key.indexOf('-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n') + 38;
    end = key.search(/\n=.*\n-----END PGP PUBLIC KEY BLOCK-----/);

    // Slice our key out
    key = key.slice(start,end);
    (debug) && console.log("Key start:end => " + start + ":" + end + "\n" + key);
    

    // Base64 decode our key 
    decoded = r2s(key);

    for (i=0; i < decoded.length;){

        // Loop over our base64 decoded key, and do byte-by-byte analysis
        var a = decoded.charCodeAt(i++);

        // If (byte AND 128) == 0, then break loop
        if ((a & 128) == 0) break; 

        // This all figures out how big our packet is based off the header
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
            if (debug) { if (a == 6) {console.log('Found Pubkey packet');} else {console.log('Found Subkey packet');}}

            // k = starting byte
            var k = i;

            // vers == next byte
            var vers=decoded.charCodeAt(i++);
            if (vers != 4) {
                (debug) && console.log('Key version => ' + vers);
                this.err = "This only supports version 4 keys right now!";
                return;
            }

            // Set version to be returned
            if (this.vers == undefined) {
            this.vers = vers;
            }

            // Timestamp of creation
            var time = (decoded.charCodeAt(i++)<<24) + (decoded.charCodeAt(i++)<<16) + (decoded.charCodeAt(i++)<<8) + decoded.charCodeAt(i++);

            // Epoch => date conversion and localization
            if (this.created == undefined){
                time = time * 1000;
                date = new Date(time)
                this.created = date.toLocaleString();
                (debug) && console.log('Created => ' + date.toLocaleString());
            }
            // If valid == 0, valid key was found (Older keys only)
            if(vers==2 || vers==3) {
                var valid=decoded.charCodeAt(i++)<<8 + decoded.charCodeAt(i++);
            }

            // This packet is our algorithm packet
            var algo = decoded.charCodeAt(i++);

            // 1 == RSA (Encrypt or Sign) and version 4 AND regular packet [Stupid RSA keys :(]
            if(algo == 1 && vers == 4 && a == 6) {
                this.type="RSA";
                primes = ['n','e'];
                a = {};
                a['n'] = "";
                a['e'] = "";
                i -= 1

                for (c=0;c<primes.length;c++){
                    size = Math.floor((decoded.charCodeAt(++i) * 256 + decoded.charCodeAt(i + 1) + 7) / 8)   
                    for (b=0;b<size;b++) {
                        a[primes[c]] += String(dec2hex(decoded.charCodeAt(i + b + 2)));
                    }
                    a[primes[c]] = a[primes[c]].split(' ')
                    i += (size +1)
                }
                this.rsaN = new BigInteger(a['n'].toString(),16)
                this.rsaE = new BigInteger(a['e'].toString(),16)
                i = i+1

            // If we have an encrypt or sign (v4) and a subkey packet
            } else if(algo == 1 && vers == 4 && a == 14) {
                this.type="RSA";
                primes = ['n','e'];
                a = {};
                a['n'] = "";
                a['e'] = "";
                i -= 1

                for (c=0;c<primes.length;c++){
                    size = Math.floor((decoded.charCodeAt(++i) * 256 + decoded.charCodeAt(i + 1) + 7) / 8)   
                    for (b=0;b<size;b++) {
                        a[primes[c]] += String(dec2hex(decoded.charCodeAt(i + b + 2)));
                    }
                    a[primes[c]] = a[primes[c]].split(' ')
                    i += (size +1)
                }
                this.rsasubN = new BigInteger(a['n'].toString(),16)
                this.rsasubE = new BigInteger(a['e'].toString(),16)
                i = i+1
                
            // 16 == ElGamal
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

                this.elgP = new BigInteger(a['p'].toString(),16)
                this.elgG = new BigInteger(a['g'].toString(),16)
                this.elgY = new BigInteger(a['y'].toString(),16)
                this.type = "DSA";

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
            // Parse out UTF-8 string of info, no need to do this twice
            if (this.user == undefined) {
            this.user = decoded.substr(i, len);
            }
            i += len;

        // If we have a signature packet for a version 4 key
        } else if (a == 2 && vers == 4) {
            // Record initial packet            
            var p = i;

            // Skip our header info
            i = i + 2;
            var alg  = decoded.charCodeAt(i++);
            var hash = decoded.charCodeAt(i++);

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
                // Read the *actual* preferred hashing algo
                } else if (ar[0] == 21) {
                    algos = new Object();
                    algos[1] = "MD5";
                    algos[2] = "SHA-1";
                    algos[3] = "RIPE-MD/160";
                    algos[8] = "SHA256";
                    algos[9] = "SHA384";
                    algos[10] = "SHA512";
                    algos[11] = "SHA224";
                    // ar[0] == packet type, first value is probably the one picked
                    this.hash = algos[ar[1]]; 
                }
                // Count up packet lengths
                i += decoded.charCodeAt(i) + 1;
            }

            // If we can't find either of these, just set them to a dummy value
            if (this.exp == undefined) {
                this.exp = "Never";
            }
            if (this.hash == undefined) {
                    algos = new Object();
                    algos[1] = "MD5";
                    algos[2] = "SHA-1";
                    algos[3] = "RIPE-MD/160";
                    algos[8] = "SHA256";
                    algos[9] = "SHA384";
                    algos[10] = "SHA512";
                    algos[11] = "SHA224";
                    this.hash = algos[hash];
            } 

            // Find out unhashed packet count, and do the same thing
            uCount = ((decoded.charCodeAt(i++)<<8) + decoded.charCodeAt(i++));
            max = i + uCount;
            while (i < max) {
                ar = [];
                // Make an array of subpacket info
                for (c=0;c<decoded.charCodeAt(i);c++) {
                    ar.push(decoded.charCodeAt(i + c + 1));
                }
                // If we found the issuer key ID
                if (ar[0] == 16) {
                    // Remove packet type
                    ar.shift();
                    a=""
                    for (t=0;t<ar.length;t++) {
                        a += String(dec2hex(ar[t]))
                    } 
                    this.id= "0x" + a.toUpperCase()
                }
                // Count up packet lengths
                i += decoded.charCodeAt(i) + 1;
            }

            // poor mans reset, stop caring about the rest of the bytes
            // which in this case is our signature values for DSA/RSA. Big woop. 
            // Would be R/S for DSA, or Z [m^d % n] for RSA
            i = p
            i += len
        } else {
            i += len;
        }
    }  
}


