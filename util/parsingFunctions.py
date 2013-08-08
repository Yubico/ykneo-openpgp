#!/usr/bin/pyton

import io
import sys
import re




#########################################################
# EXTRACT THE SINGLE PARAMETERs FROM A OPENSSL KEY FILE #
#########################################################

#
#parse_key_file:(data, key): 
#extracts modulus, private exponent, prim1, prime2, exponent1, exponent2, coeffiecient from an openssl key file
#
def parse_key_file(data, key):


    
    result = re.search(r'(modulus:\n)(.+)(\npublicExponent:)', data, re.DOTALL)
    if result:
        key["modulus"] = result.group(2).translate(None, ' \n')
    else:
        print "dedaly error modulus"
        sys.exit(1)
    
    result = re.search(r'(publicExponent: )(\d+)(.+)(privateExponent:)', data, re.DOTALL)
    if result:
        key["publicExponent"] = result.group(2)
        if not result.group(2) == "65537":
           print "the publicExponent is not 65537, press (c)ontinue anything else to (e)xit"
           var = raw_input(">>")
           if not var == "c":
               print "User Exit"
               sys.exit(0)
        
    else:
        print "The public exponent is not 65537"
        sys.exit(1)

    
    result = re.search(r'(privateExponent:\n)(.+)(\nprime1:)', data, re.DOTALL)
    if result:
        key["privateExponent"] = result.group(2).translate(None, ' \n')
    else:
        print "dedaly error privateExponent"
        sys.exit(1)

    result = re.search(r'(prime1:\n)(.+)(\nprime2:)', data, re.DOTALL)
    if result:
        key["prime1"] = result.group(2).translate(None, ' \n')
    else:
        print "dedaly error prime1"
        sys.exit(1)

    result = re.search(r'(prime2:\n)(.+)(\nexponent1:)', data, re.DOTALL)
    if result:
        key["prime2"] = result.group(2).translate(None, ' \n')
    else:
        print "dedaly error prime2"
        sys.exit(1)

    result = re.search(r'(exponent1:\n)(.+)(\nexponent2:)', data, re.DOTALL)
    if result:
        key["exponent1"] = result.group(2).translate(None, ' \n')
    else:
        print "dedaly error exponent1"
        sys.exit(1)    

    result = re.search(r'(exponent2:\n)(.+)(\ncoefficient:)', data, re.DOTALL)
    if result:
        key ["exponent2"] = result.group(2).translate(None, ' \n')
    else:
        print "dedaly error exponent2"
        sys.exit(1)

    result = re.search(r'(coefficient:\n)(.+)(\n-----BEGIN RSA PRIVATE KEY-----)', data, re.DOTALL)
    if result:
        key["coefficient"] = result.group(2).translate(None, ' \n')
    else:
        print "dedaly error coefficient"
        sys.exit(1)
        

    return key









#
#parse_fingerprint_file:(fingerprintData): extract fingerprint for the selected key
#
def parse_fingerprint_file(fingerprintData, keyid):
    

    keyid = keyid[-4:]
    regexp = r"^\s+Key fingerprint = (.+?)" + keyid +"$"
    
    result = re.search(regexp, fingerprintData, re.MULTILINE)
    if result:
        fingerprint = result.group(1)+keyid
        fingerprint = fingerprint.translate(None, ' ')
    else:
        print "dedaly error fingerprint"
        sys.exit(1)
    
    return fingerprint
