import argparse,hashlib,base64,timeit

def main():

    parser = argparse.ArgumentParser(description='PBKDF2 hashing with base64 and hex output')
    parser.add_argument('-H','--help_extended',action='store_true',help='Extended help; for regular help use -h.')
    parser.add_argument('-a','--algorithm',help='This is the algorithm to use - if you really need it, SHA-1 is available but is not recommended, and MD5 is included for idiots or benchmarkers.',choices=['SHA-512','SHA-384','SHA-256','SHA-224','SHA-1','MD5'])    
    parser.add_argument('-p','--password',help='This is the password to hash.')
    parser.add_argument('-P','--passwordfmt',help='NOT YET IMPLEMENTED - always string')
    parser.add_argument('-s','--salt',help='This is the salt to use in encoding, often we use the text to encode.')
    parser.add_argument('-S','--saltfmt',help='NOT YET IMPLEMENTED - always string')
    parser.add_argument('-i','--iterations', type=int,help='This is the number of iterations.')
    parser.add_argument('-o','--outputBytes',type=int,help='This is the output length in bytes - if in doubt, use 64 if you use sha512, and 48 if you use sha384, and 32 if you use sha256, and 28 if you use sha224, and if you absolutely must, 20 if you use sha1, and if you are a complete idiot or a benchmarker, 16 for md5.')
    parser.add_argument('-O','--outputfmt',help='NOT YET IMPLEMENTED - always string')
    parser.add_argument('-e','--expected',help='This is the expected output in hexadecimal of either case.')
    parser.add_argument('-n','--interactive',action='store_true',help='Interactive mode; NOT YET IMPLEMENTED')    
    args = parser.parse_args()
    if args.help_extended:
        print ("Use -h for help and -H for extended help.")
        print ("Test vectors for SHA512 at: http://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors")
        print ("    sha512 example: password = password    salt = salt   iterations = 4096  outputBytes = 64   hash = SHA-")
        print ("    output (hex) should be: d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5")
        print ("Test vectors for SHA256 at: http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors")
        print ("    sha256 example: password = password    salt = salt   iterations = 4096  outputBytes = 32   hash = SHA-256")
        print ("    output (hex) should be: c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        print ("Test vectors for SHA1 at: http://tools.ietf.org/html/rfc6070")
        print ("    sha1 example: password = password    salt = salt   iterations = 4096  outputBytes = 20   hash = SHA-1")
        print ("    output (hex) should be: 4b007901b765489abead49d926f721d065a429c1")

        print ("Example (linux, with python installed): python ./CLIpbkdf2.py -p 'password' -s 'salt' -i 524288 -o 48 -a 'SHA-384'")
        print ('Example (Windows, with python installed): python CLIpbkdf2.py -p "password" -s "salt" -i 524288 -o 48 -a SHA-384')
        print ('Example (Windows, CLIpbkdf2.exe, PyInstaller directory): clipbkdf2 -p "password" -s "salt" -i 4096 -o 32 -a SHA-256')

        return
    if args.algorithm == 'SHA-256':
        BinaryOutput = hashlib.pbkdf2_hmac('sha256',args.password, args.salt, args.iterations, args.outputBytes)
    elif args.algorithm == 'SHA-384':
        BinaryOutput = hashlib.pbkdf2_hmac('sha384',args.password, args.salt, args.iterations, args.outputBytes)
    elif args.algorithm == 'SHA-512':
        BinaryOutput = hashlib.pbkdf2_hmac('sha512',args.password, args.salt, args.iterations, args.outputBytes)
    elif args.algorithm == 'SHA-224':
        BinaryOutput = hashlib.pbkdf2_hmac('sha224',args.password, args.salt, args.iterations, args.outputBytes)
    elif args.algorithm == 'SHA-1':
        BinaryOutput = hashlib.pbkdf2_hmac('sha1',args.password, args.salt, args.iterations, args.outputBytes)
    elif args.algorithm == 'MD5':
        BinaryOutput = hashlib.pbkdf2_hmac('md5',args.password, args.salt, args.iterations, args.outputBytes)
    if args.expected:
        if hashlib.sha256(args.expected.lower()).hexdigest() == hashlib.sha256(BinaryOutput.encode('hex')).hexdigest():
            print ('1')
        else:
            print ('0')
    else:
        print ('Base64 (RFC1521 MIME, PEM - extra chars are + and /, while padding is =):')
        print (BinaryOutput.encode('base64'))
        print ('Base64 (urlsafe - extra chars are - and _, while padding is =):')
        print (base64.urlsafe_b64encode(BinaryOutput))
        print ('')
        print ('Base32 (A-Z, 2-7, padding is =):')
        print (base64.b32encode(BinaryOutput))
        print ('')
        print ('Base16 (uppercase hex):')
        print (base64.b16encode(BinaryOutput))
        print ('')
        print ('hex (lowercase):')
        print (BinaryOutput.encode('hex'))
        print ('')
    

if __name__=="__main__":
    main()
