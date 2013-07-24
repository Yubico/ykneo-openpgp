#!/usr/bin/pyton

import io
import os
import sys
import math
import subprocess
import re

#
# strip_zero_byte: just removes the leadin 0 bytes, for readability moved in functions.py
#
def strip_zero_byte(key):

    for label, value in key.items():
        key[label] = value.lstrip('0:')
        
    return key





#
# counts the bytse in of each components of the openssl key format
#
def key_size(key):
    
    for label, value in key.items():
         
        bytesize = value.count(':')
        value  = [value, "1"]
        key[label] = value
        key[label][1] = bytesize+1 #+1 because there is one byte more then columns (:) separator
        
    return key




#
# determine the size of the payload command, moved here for readability 
#
def payload_size(byte_size, key):
    
    byte_size["payload"] = ( 
        key["modulus"][1] +
        key["publicExponent"][1] +
        key["prime1"][1] +
        key["prime2"][1] +
        key["exponent1"][1] +
        key["exponent2"][1] +
        key["coefficient"][1]
        )
        
    return byte_size




    
#
# prepend ZERO ( 0 ) : moved here for readability. 
#
def prepend_zero(string):
    
    if (len(string))%2 == 1:
        string = "0" + string
        
    return string 




#
# Returns the byte size encoded in BER encoding. This will be used in the final command
#
def return_ber_length(size):
    
    result = ""
    
    if 0 < size < 128:
        result = prepend_zero(hex(size).lstrip("0x"))
    elif 128 <= size < 256:
        result = ''.join(["81 ", prepend_zero(hex(size).lstrip("0x"))])
    elif 256 <= size < 65535:
        result = ''.join(["82 ", prepend_zero(hex(size).lstrip("0x"))])

    else:
        print "Error: byte size > 65535 check input"
        sys.exit(1)

    
    return result




#
# Returns the payload formatted for the opensc command diveded in chunks of 255 or less
#
def build_payload(key):
    
    payload = ""
    
    for label, value in key.items():
        
        if label == "privateExponent":
            print "NOTICE: Skipping private exponent."
        else:
            payload = payload + " " + key[label][0]
  
    return payload.replace(":"," ")  
            


            
#
# insert whitespace every 2 characters into a specific string
#
def insert_whitespace(string, every=2):
    return ' '.join(string[i:i+every] for i in xrange(0, len(string), every)) 





#
# counts the bytse in a string
#
def byte_count(string):
      
    bytesize = string.count(' ')
    bytesize += 1 #+1 because there is one byte more then whitespace " " separator
    
    return bytesize



### END OF UTILITY FUNCTIONS ###
################################



#########################################################
#                                                       #  
# Below the two functions that build the final command: #
# build_command and chunk_builder                       #
#                                                       #
# Build Command will create the pieces of the puzzle,   #
# chunk builder will assemble them                      #
#                                                       #                      
#########################################################




#############################################################
#                                                           #
# chunk_builder buils the final result which is returned to #
# build_command. Build_command return to keyParser.py       #
#                                                           #
#############################################################

#
# chunk_builder: builds the final command, using 250bytes block + 4 byte command and +1 byte size
#
def chunk_builder(payload, chuckSize, lastChunkSize, chunksNum, commandPart):
    
    #initialization of some temp variables
    listOfChunks = []
    i=0 
    temp = ""
    byteNum = 0
    
    #build block structure
    block = (commandPart["commandOption"] + commandPart["singleQuote"] + 
            commandPart["firstChunk"] + (hex(chuckSize)).lstrip('0x') + " ")
    endBlock = (commandPart["commandOption"] + commandPart["singleQuote"] + 
            commandPart["lastChunk"] + (hex(lastChunkSize)).lstrip('0x') + " " )
    
    
    
    #this for loop builds 255 byte long chunks (250 + 4 command +1 for size)
    for c in payload:
        whitespace = 0
        temp = temp + c
        if c == " ":
            byteNum = byteNum +1
            #chunkSize is set to 250byte in function build_command
            if byteNum == chuckSize:
                listOfChunks.append(temp)
                temp = ""
                byteNum = 0
            
    #append the remaining byte for the last chunk    
    listOfChunks.append(temp)            
    
    #trim possible white space remaining at the end of the chunks and assemble blocks
    #not sure this is very pythonian...
    for element in listOfChunks[:-1]:
        listOfChunks[i] = block + element.rstrip(" ") + commandPart["singleQuote"]
        i+=1
        
    #build the last block which begins with a different byte code and trim white space
    listOfChunks[i] = endBlock + element.rstrip(" ") + commandPart["singleQuote"]
    
    #join the chunks
    temp = ''.join(listOfChunks)
    #build the final command
    finalCommand = (commandPart["commandStart"] + temp)

    return finalCommand
    





#
# BUILD COMMAND: takes all command components and builds them into a full command
#
def build_command(byte_size, key, keyType):
    
    #define the size of a full chunk
    chunkSize = 250
    payloadSize = 0
    finalCommand = ""
    #here we will build single command components
    commandPart = {}
    
    
    #building chuck sizes
    byte_size["template"] = byte_size["payload"] +14 #14 byte for commands
    byte_size["header"] = byte_size["template"] + 8 #8 byte for the commands
    byte_size["publicExponent"] = key["publicExponent"][1]
    byte_size["prime1"] = key["prime1"][1]
    byte_size["prime2"] = key["prime2"][1]
    byte_size["coefficient"] = key["coefficient"][1]
    byte_size["exponent1"] = key["exponent1"][1]
    byte_size["exponent2"] = key["exponent2"][1]
    byte_size["modulus"] = key["modulus"][1]
    byte_size["tail"] = byte_size["payload"]
    
    
    
    
    #######################################
    # Building the command piece by piece #
    #######################################
    #
    # NOTE: whitespace is always at the end of the parameter!
    #
    commandPart["commandStart"] = "opensc-tool -s '00 A4 04 00 06 D2 76 00 01 24 01'"
    commandPart["commandOption"] = " -s "
    commandPart["singleQuote"] = "\'"
    commandPart["firstChunk"] = "10 db 3f ff "
    commandPart["1"] = "4d "+return_ber_length(byte_size["header"])+" " 
    commandPart["2"] =  keyType+" 00 "
    commandPart["3"] = "7f 48 "+return_ber_length(byte_size["template"])+" "
    commandPart["4"] = "91 "+return_ber_length(byte_size["publicExponent"])+" "
    commandPart["5"] = "92 "+return_ber_length(byte_size["prime1"])+" "
    commandPart["6"] = "93 "+return_ber_length(byte_size["prime2"])+" "
    commandPart["7"] = "94 "+return_ber_length(byte_size["coefficient"])+" "
    commandPart["8"] = "95 "+return_ber_length(byte_size["exponent1"])+" "
    commandPart["9"] = "96 "+return_ber_length(byte_size["exponent2"])+" "
    commandPart["10"] = "97 "+return_ber_length(byte_size["modulus"])+" "
    commandPart["11"] = "5f 48 "+return_ber_length(byte_size["payload"])+" "
    commandPart["payload"] = build_payload(key)
    commandPart["lastChunk"] = "00 db 3f ff "
    
    
    
    
    #assemble the total command and count how many bytes we have
    payload = (commandPart["1"] + commandPart["2"] + 
                      commandPart["3"] + commandPart["4"] + commandPart["5"] + 
                      commandPart["6"] + commandPart["7"] + commandPart["8"] + 
                      commandPart["9"] + commandPart["10"]+ commandPart["11"]+ 
                      commandPart["payload"])
    
    
    #sanitize payload by removing all white space
    payload = payload.translate(None, ' ')
    #format payload with a white space every byte
    payload = insert_whitespace(payload)
    #count how many bytes are stored in the payload
    payloadSize = byte_count(payload)
       
    
    #compute how many packets we need to send the whole command
    #maximum size is 255 byte, but 5 bytes are used by "command_begin + command_size"
    #so we can get rid only of 250 bytes per command part
    #each command part starts with -s option
    
    chunksNum = int(math.ceil(float(byte_count(payload)) / 250))
    lastChunkSize = payloadSize % 250
    
    #at this point the payload is formatted and ready to be attached in the command    
    finalCommand = chunk_builder(payload, chunkSize, lastChunkSize, chunksNum, commandPart)
    
    
    
    #DEBUG
    #print "printing command parts"
    #for k, v in commandPart.items(): print k, '>', v
    
    #DEBUG:
    #print "deadly command:"
    #for value in commandPart.values():
    #    print "Param:"
    #    print value    
    
    
    return finalCommand









# END OF COMMAND BUILDING FUNCTIONS #
#####################################




#######################################################################
#                                                                     #
# Fingerprint build function: returns the command for the fingerprint #
#                                                                     # 
#######################################################################


#
# build_fingerprint: build the command conversion for the fingerprint
#
def build_fingerprint(fingerprint, keyType):
    
    
    fingerprint = insert_whitespace(fingerprint)
    #command parts
    commandParts = {}
    
    
    #NOTICE: if white space is needed is always at the end of the string!
    commandParts["commandName"] = "opensc-tool -s '00 A4 04 00 06 D2 76 00 01 24 01' "
    commandParts["commandOption"] = "-s "
    commandParts["commandBegin"] = "00 da 00 "
    commandParts["keyType"] = keyType+" "
    commandParts["byteSize"] = return_ber_length(byte_count(fingerprint))+" "
    commandParts["payload"] = fingerprint
    commandParts["singleQuote"] = "\'"
    
    command = (commandParts["commandName"] + commandParts["commandOption"] +
               commandParts["singleQuote"] + commandParts["commandBegin"] +
               commandParts["keyType"] + commandParts["byteSize"] +
               commandParts["payload"] + commandParts["singleQuote"])
    
    return command


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
def parse_fingerprint_file(fingerprintData):
    
    result = re.search(r'(Key fingerprint = )(.+)(\nuid)', fingerprintData, re.DOTALL)
    if result:
        fingerprint = result.group(2).translate(None, ' ')
    else:
        print "dedaly error fingerprint"
        sys.exit(1)
    
    return fingerprint



#check if the program was executed correctly with user input
if len(sys.argv) != 4:
    print("\nUsage: python keyParser.py keyFormat fingerprintType keyID  (i.e. python keyParser.py B6 C9 1A4FFEBA")
    sys.exit(2)


##################
# Initialization #
##################

#defines key structure [ VALUE , NUM BYTE SIZE]
key = {}
#define key parameters size with this structure
byte_size = {'payload':int(0)}

#user input keytype - defined at user input, indicates the Key Type
keyType = sys.argv[1]
fingerprintType = sys.argv[2]
keyID = sys.argv[3]

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
p1 = subprocess.Popen(["env", "LANG=C","gpg","--export-secret-key", keyID], stdout=subprocess.PIPE)
p2 = subprocess.Popen(["env", "LANG=C", "openpgp2ssh", keyID], stdin=p1.stdout, stdout=subprocess.PIPE)
p3 = subprocess.Popen(["env", "LANG=C", "openssl","rsa","-text"], stdin=p2.stdout, stdout=subprocess.PIPE)
output = p3.communicate()[0]
file = open(filenameKEY, "w")
file.write(output)
file.close()

#generate fingerprint file
p = subprocess.Popen(["env", "LANG=C", "gpg", "--fingerprint", keyID], stdout=subprocess.PIPE)
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
key = parse_key_file(keyData, key)

#parse the fingerprint file
fingerprint = parse_fingerprint_file(fingerprintData)


#strip leading 0 bytes from key parameters - as requested from Klas
key = strip_zero_byte(key)

#count number of bytes per parameter in the key
key = key_size(key)

#convert public exponent to hex and compute size in byte. 
#the publicExponent is threated separately becuase it has its own format in the key file
key["publicExponent"][0] = hex(int(key["publicExponent"][0])).lstrip("0x")
#count the size and ceil up, for the minimum number of bytes to store the value
key["publicExponent"][1] = int(math.ceil(float(len(key["publicExponent"][0]))/2))
#add 0 padding for the size of the exponent (usually 5 char 10001)
key["publicExponent"][0] = prepend_zero(key["publicExponent"][0])


#simple function compute total payload (just for readability)
byte_size = payload_size(byte_size, key)


#Build the final command with the commandPart and the specific byte_size
keycmd = build_command(byte_size, key, keyType)

#build the final fingerprint command
fingercmd = build_fingerprint(fingerprint, fingerprintType)
  

#print result
print "\nKEY conversion :\n"
print keycmd
#print result
print "\nFingerprint conversion:\n"
print fingercmd





#exit without errors
sys.exit(0)
