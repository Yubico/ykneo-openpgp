#!/usr/bin/python

import io
import os
import sys
import math
import subprocess
import parsingFunctions as pf
import functions as f



#check if the program was executed correctly with user input
if len(sys.argv) != 4:
    print("\nUsage: python keyParser.py {a|s|e} keyID pincode (i.e. python keyParser.py e 1A4FFEBA smartcard_pincode")
    sys.exit(2)


##################
# Initialization #
##################

#defines key structure [ VALUE , NUM BYTE SIZE]
key = {}
#define key parameters size with this structure
byte_size = {'payload':int(0)}

#user input keytype - defined at user input, indicates the Key Type
keyPurpose = sys.argv[1]
keyID = sys.argv[2]
pincode = sys.argv[3]

if keyPurpose == 'a':
  keyType = 'A4'
  fingerprintType = 'C9'
elif keyPurpose == 's':
  keyType = 'B6'
  fingerprintType = 'C7'
elif keyPurpose == 'e':
  keyType = 'B8'
  fingerprintType = 'C8'
else:
  print("\nUsage: python keyParser.py {a|s|e} keyID pincode (i.e. python keyParser.py e 1A4FFEBA smartcard_pincode")
  sys.exit(2)

filenameKEY = "keyFile"
filenameFINGER = "keyFingerprint"
# remove existing copy of these file
if os.path.isfile(filenameKEY):
    os.remove(filenameKEY)
if os.path.isfile(filenameFINGER):
    os.remove(filenameFINGER)
    


####################
# generating files #
####################

#generate key file
p1 = subprocess.Popen(["gpg", "--export-secret-key", keyID], stdout=subprocess.PIPE)
p2 = subprocess.Popen(["openpgp2ssh", keyID], stdin=p1.stdout, stdout=subprocess.PIPE)
p3 = subprocess.Popen(["openssl","rsa","-text"], stdin=p2.stdout, stdout=subprocess.PIPE)
output = p3.communicate()[0]
file = open(filenameKEY, "w")
file.write(output)
file.close()

#generate fingerprint file
p = subprocess.Popen(["gpg", "--fingerprint","--fingerprint", keyID], stdout=subprocess.PIPE)
output, err = p.communicate()
file = open(filenameFINGER, "w")
file.write(output)
file.close()


#read the key file content into memory
file = open (filenameKEY, 'r')
keyData = file.read()
file.close()
#read the fingerprint file content into memory
file = open (filenameFINGER, 'r')
fingerprintData = file.read()
file.close()



###############
# Computation #
###############

#parse a key file and builds the key parameters
key = pf.parse_key_file(keyData, key)

#parse the fingerprint file
fingerprint = pf.parse_fingerprint_file(fingerprintData, keyID)

#strip leading 0 bytes from key parameters - as requested from Klas
key = f.strip_zero_byte(key)

#count number of bytes per parameter in the key
key = f.key_size(key)

#convert public exponent to hex and compute size in byte. 
#the publicExponent is threated separately becuase it has its own format in the key file
key["publicExponent"][0] = hex(int(key["publicExponent"][0])).lstrip("0x")
#count the size and ceil up, for the minimum number of bytes to store the value
key["publicExponent"][1] = int(math.ceil(float(len(key["publicExponent"][0]))/2))
#add 0 padding for the size of the exponent (usually 5 char 10001)
key["publicExponent"][0] = f.prepend_zero(key["publicExponent"][0])


#simple function compute total payload (just for readability)
byte_size = f.payload_size(byte_size, key)



#build the final fingerprint command
fingerpart = f.build_fingerprint(fingerprint, fingerprintType)

#Build the final command with the commandPart and the specific byte_size
keycmd = f.build_command(byte_size, key, keyType, pincode, fingerpart)


#print result
print "\nKEY conversion :\n"
print keycmd
#print result
#print "\nFingerprint conversion:\n"
#print fingercmd





#exit without errors
sys.exit(0)
