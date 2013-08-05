#!/usr/bin/python

import io
import os
import sys
import math


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
        value = [value, "1"]
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
# hexfy_ascii, convert a ascii string values "93 45 23 45 67" from ascii to hex
#
def hexfy_ascii(ascii):
    
    mylist = ascii.split(' ')
    for idx, val in enumerate(mylist):
        mylist[idx] = hex(int(val)).lstrip('0x')

    mystring = ''.join(mylist)
    mystring = insert_whitespace(mystring)
        
    return mystring


#
# pincode_formatter takes a pincode converts it to ascii and calculates the length. 
#
def pincode_formatter(pincode):

	ascii = ''.join(str(ord(c)) for c in pincode)
	#default 00 20 00 83 08 31 32 33 34 35 36 37 38
	ascii = insert_whitespace(ascii)
	#count the length of the pin
	size = byte_count(ascii)
	#convert it to hex
	size = hex(size)
        size = size.lstrip('0x')
        #add zero 
        size = prepend_zero(size)
        if len(size) > 2:
            size = insert_whitespace(size)
        
        asciihex = hexfy_ascii(ascii)

	#build the string
	pincode = "00 20 00 83 "+ size + " " + asciihex
	
	print pincode
	
	return pincode


#
# Returns the payload formatted for the opensc command diveded in chunks of 255 or less
#
def build_payload(key):
    """
    payload = ""
    
    for label, value in key.items():
        
        if label == "privateExponent":
            print "NOTICE: Skipping private exponent."
        else:
            payload = payload + " " + key[label][0]
    """

    payload = []
    payload.append(key["publicExponent"][0])
    payload.append(key["prime1"][0])
    payload.append(key["prime2"][0])
    payload.append(key["coefficient"][0])
    payload.append(key["exponent1"][0])
    payload.append(key["exponent2"][0])
    payload.append(key["modulus"][0])
    
    mystring = ''.join(payload)
    

    return mystring.replace(":"," ")  
            


            
#
# insert whitespace every 2 characters into a specific string
#
def insert_whitespace(string, every=2):
    return ' '.join(string[i:i+every] for i in xrange(0, len(string), every)) 





#
# counts the bytes in a string representing a byte list
#
def byte_count(string):
      
    bytesize = string.count(' ')
    bytesize += 1 #+1 because there is one byte more then whitespace " " separator
    
    return bytesize



def return_template_size(byte_size):


    value = (return_ber_length(byte_size["publicExponent"])+
             return_ber_length(byte_size["prime1"])+
             return_ber_length(byte_size["prime2"])+
             return_ber_length(byte_size["coefficient"])+
             return_ber_length(byte_size["exponent1"])+
             return_ber_length(byte_size["exponent2"])+
             return_ber_length(byte_size["modulus"]))

    #sanitize payload by removing all white space
    value = value.translate(None, ' ')
    #format payload with a white space every byte
    value = insert_whitespace(value)
    #count how many bytes are stored in the payload
    size = byte_count(value)
    

    return size+7#7 is the number of byte for commands openpgp.pdf


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
def chunk_builder(payload, chuckSize, lastChunkSize, chunksNum, commandPart, fingerpart):
    
    #initialization of some temp variables
    listOfChunks = []
    i=0 
    temp = ""
    byteNum = 0
    tempList = []
    
    #build block structure
    block = (commandPart["commandOption"] + commandPart["singleQuote"] + 
            commandPart["firstChunk"] + (hex(chuckSize)).lstrip('0x') + " ")
    endBlock = (commandPart["commandOption"] + commandPart["singleQuote"] + 
            commandPart["lastChunk"] + (hex(lastChunkSize)).lstrip('0x') + " " )
    
    
    #this for loop builds 255 byte long chunks (250 + 4 command +1 for size)
    for c in payload:
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
        tempList.append(block + element.rstrip(" ") + commandPart["singleQuote"])
        
        
    #build the last block which begins with a different byte code and trim white space
    tempList.append(endBlock + listOfChunks[-1].rstrip(" ") + commandPart["singleQuote"])

    
    #join the chunks
    temp = ''.join(tempList)
    #build the final command
    finalCommand = (commandPart["commandStart"] + commandPart["pincode"] + temp + fingerpart)

    return finalCommand
    





#
# BUILD COMMAND: takes all command components and builds them into a full command
#
def build_command(byte_size, key, keyType, pincode, fingerpart):
    
    #define the size of a full chunk
    chunkSize = 250
    payloadSize = 0
    finalCommand = ""
    #here we will build single command components
    commandPart = {}
    
	#convert the pincode into ascii and calculate pincode length
    pincode = pincode_formatter(pincode)
	
    
    #building chuck sizes
    byte_size["publicExponent"] = key["publicExponent"][1]
    byte_size["prime1"] = key["prime1"][1]
    byte_size["prime2"] = key["prime2"][1]
    byte_size["coefficient"] = key["coefficient"][1]
    byte_size["exponent1"] = key["exponent1"][1]
    byte_size["exponent2"] = key["exponent2"][1]
    byte_size["modulus"] = key["modulus"][1]
    byte_size["tail"] = byte_size["payload"]
    byte_size["template"] = return_template_size(byte_size)
    byte_size["header"] = byte_size["template"]+byte_size["payload"]+2#2 is the byte for key type definition b6 00
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
    commandPart["pincode"] = " -s '" + pincode + "'"
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
    finalCommand = chunk_builder(payload, chunkSize, lastChunkSize, chunksNum, commandPart, fingerpart)
    
    
    
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
    commandParts["commandName"] = "opensc-tool -s '00 A4 04 00 06 D2 76 00 01 24 01'"
    commandParts["commandOption"] = " -s "
    commandParts["commandBegin"] = "00 da 00 "
    commandParts["keyType"] = keyType+" "
    commandParts["byteSize"] = return_ber_length(byte_count(fingerprint))+" "
    commandParts["payload"] = fingerprint
    commandParts["singleQuote"] = "\'"
    
    #command = (commandParts["commandName"] + commandParts["commandOption"] +
    #           commandParts["singleQuote"] + commandParts["commandBegin"] +
    #           commandParts["keyType"] + commandParts["byteSize"] +
    #           commandParts["payload"] + commandParts["singleQuote"])
    
    #old version was returning 2 separate commands
    #return command
    
    fingerprint = (commandParts["commandOption"] +
               commandParts["singleQuote"] + commandParts["commandBegin"] +
               commandParts["keyType"] + commandParts["byteSize"] +
               commandParts["payload"] + commandParts["singleQuote"])


    return fingerprint
    
    
    
