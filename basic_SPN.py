#A basic Substitution-Permutation Network cipher, implemented by following 
#'A Tutorial on Linear and Differential Cryptanalysis'
# by Howard M. Heys
#
# 02/12.16 Alice Hicks 
#
#Basic SPN cipher which takes as input a 16-bit input block and has 4 rounds.
#Each round consists of (1) substitution (2) transposition (3) key mixing

import random
import hashlib

blockSize = 16

#(1) Substitution: 4x4 bijective, one sbox used for all 4 sub-blocks of size 4. Nibble wise
sbox = {0:0xE, 1:0x4, 2:0xD, 3:0x1, 4:0x2, 5:0xF, 6:0xB, 7:0x8, 8:0x4, 9:0xA, 0xA: 0x6, 0xB: 0xC, 0xC:0x5, 0xD:0x9, 0xE: 0x0, 0xF:0x7} #key:value
sbox_inv = {}

#Apply sbox (1) to a 16 bit state and return the result
def apply_sbox(state, sbox):
    subStates = [state&0x000f, (state&0x00f0)>>4, (state&0x0f00)>>8, (state&0xf000)>>12]
    for idx,subState in enumerate(subStates):
        subStates[idx] = sbox[subState]
    return subStates[0]|subStates[1]<<4|subStates[2]<<8|subStates[3]<<12
    

#(2) Permutation. Bit wise
pbox = {0:0, 1:4, 2:8, 3:12, 4:1, 5:5, 6:9, 7:13, 8:2, 9:6, 10:10, 11:14, 12:3, 13:7, 14:11, 15:15}

#(3) Key mixing: bitwise XOR between round subkey and data block input to round
# Key schedule: independant random round keys. 
k = hashlib.sha1( hex(random.getrandbits(blockSize*8)).encode('utf-8') ).hexdigest()[2:]
subKeys = [int(subK,16) for subK in [ k[0:4],k[4:8], k[8:12], k[12:16] ]]

def encrypt(pt):
    state = pt
    
    #First three rounds of sinple SPN cipher
    for roundN in range(0,1):
    
        #XOR state with round key (3)
        state = state^subKeys[roundN]
        print (hex(state))
        
        #Break state into nibbles, perform sbox on each nibble, write to state (1)
        state = apply_sbox(state,sbox)
        
        #Permute the state bitwise (2)
        state_temp = 0      
        for bitIdx in range(0,blockSize):
            if(state & (1 << bitIdx)):
                state_temp |= (1 << pbox[bitIdx])
        state = state_temp
    
    #Final round of SPN cipher
    state = state^subKeys[-1] #Final key mixing
    state = apply_sbox(state,sbox) #Final substituion
    
    return state
	        
print ('{:04x}'.format(encrypt(0xBBAA)))                
