# Linear cryptanalysis of a basic SPN cipher
# Try to determine linear expressions between input and output bits which have
# a linear probability bias. Randomly chosen bits would only satisfy the 
# expression with probability 0.5 (Matsui's Piling up Lemma)

import basic_SPN as cipher
from math import trunc, fabs
import itertools as it
import collections

# Return bit n from (int) bits of intended bit-length 4
def getNibbleBit(bits, n):
    return int(bin(bits)[2:].zfill(4)[n])

# Return bit n from (int) bits of intended bit-length 16    
def getShortBit(bits, n):
    return int(bin(bits)[2:].zfill(16)[n])    

# Build table of input values
sbox_in = ["".join(seq) for seq in it.product("01", repeat=4)]
# Build a table of output values
sbox_out = [ bin(cipher.sbox[int(seq,2)])[2:].zfill(4) for seq in sbox_in ]
# Build an ordered dictionary between input and output values
sbox_b = collections.OrderedDict(zip(sbox_in,sbox_out))
# Initialise LAT
probBias = [[0 for x in range(len(sbox_b))] for y in range(len(sbox_b))] 

print('Linear Approximation Table for basic SPN cipher\'s sbox: ')
for bits in sbox_b.items():
    input_bits, output_bits = bits
    X1,X2,X3,X4 = [ int(bits,2) for bits in [input_bits[0],input_bits[1],input_bits[2],input_bits[3]] ]
    Y1,Y2,Y3,Y4 = [ int(bits,2) for bits in [output_bits[0],output_bits[1],output_bits[2],output_bits[3]] ]
                
    equations_in = [0, X4, X3, X3^X4, X2, X2^X4, X2^X3, X2^X3^X4, X1, X1^X4,
                    X1^X3, X1^X3^X4, X1^X2, X1^X2^X4, X1^X2^X3, X1^X2^X3^X4] 
                    
    equations_out = [0, Y4, Y3, Y3^Y4, Y2, Y2^Y4, Y2^Y3, Y2^Y3^Y4, Y1, Y1^Y4,
                    Y1^Y3, Y1^Y3^Y4, Y1^Y2, Y1^Y2^Y4, Y1^Y2^Y3, Y1^Y2^Y3^Y4]                
    
    for x_idx in range (0, len(equations_in)):
        for y_idx in range (0, len(equations_out)):
            probBias[x_idx][y_idx] += (equations_in[x_idx]==equations_out[y_idx])

# print linear approximation table
for bias in probBias:
    for bia in bias:
        #trunc(((bia/16.0)-0.5)*16.0)
        print('{:d}'.format(bia-8).zfill(2), end=' ')
    print('')
    
# Constructing Linear Approximations for the Complete Cipher
# We concatenate linear approximations through multiple rounds
# See README: Appendix, Figure 1 for working out
# -
# U_4,6 ^ U_4,8 ^ U_4,14 ^ U_4,14 ^ U_4,16 ^ P_5 ^ P_7 ^ P_8 = SK
# SK = K_1,5 ^ K_1,7 ^ K_1,8 ^ K_2,6 ^ K_3,6 ^ K_3,14 ^ K_4,6 ^ K_4,8 ^ K_4,14 ^ K_4,16
# must hold with a probability of 15/32
# We can leverage this approximation to recover bits of the last subkey (K_5)

# Extracting key bits: checking target partial subkey bits
#
# target partial subkey bits are the bits from the last subkey associated with the S-boxes in
# the last round influenced by the data bits involved in the linear approximation
# the correct partial subkey value will result in the linear approximation holding with a probability 
# significantly different from 0.5


#For all possible values of the target partial subkeys, the corresponding
#ciphertext bits are exclusive-ORed with the bits of the target partial subkey and the result
#is run backwards through the corresponding S-boxes. 

#This is done for all known plaintext/ciphertext samples and a count is kept for each value of the target partial
#subkey. The count for a particular target partial subkey value is incremented when the
#linear expression holds true for the bits into the last round’s S-boxes (determined by the
#partial decryption) and the known plaintext bits. 

#The target partial subkey value which has the count which differs the greatest from half the number of plaintext/ciphertext
#samples is assumed to represent the correct values of the target partial subkey bits. This
#works because it is assumed that the correct partial subkey value will result in the linear
#approximation holding with a probability significantly different from 1/2. 

#An incorrect subkey is assumed to result in a relatively random guess at the bits entering the S-boxes of the last round and as a result, the linear
#expression will hold with a probability close to 1/2.

#The linear expression U_4,6 ^ U_4,8 ^ U_4,14 ^ U_4,14 ^ U_4,16 ^ P_5 ^ P_7 ^ P_8 = 0 affects the
#inputs to S-boxes S_4,2 and S_4,4 in the last round. For each plaintext/ciphertext sample, we
#would try all 256 values for the target partial subkey [K_5,5 ...K_5,8 , K_5,13 ...K_5,16 ]. 

#For each partial subkey value, we would increment the count whenever equation (5) holds true,
#where we determine the value of [U_4,5 ...U_4,8 , U_4,13 ...U_4,16 ] by running the data backwards
#through the target partial subkey and S-boxes S_2,4 and S_4,4 . The count which deviates the
#largest from half of the number of plaintext/ciphertext samples is assumed to the correct
#value.

#We have simulated attacking our basic cipher by generating 10000 known
#plaintext/ciphertext values and following the cryptanalytic process described for partial
#subkey values [K 5,5 ...K 5,8 ] = [0010] (hex 2) and [K 5,13 ...K 5,16 ] = [0100] (hex 4). As
#expected, the count which differed the most from 5000 corresponded to target partial
#subkey value [2,4] hex , confirming that the attack has successfully derived the subkey bits.
#Table 5 highlights a partial summary of the data derived from the subkey counts. (The
#complete data involves 256 data entries, one for each target partial subkey value.) The
#values in the table indicate the bias magnitude derived from

k = cipher.keyGeneration()
k5_bin = bin(int(k,16))[2:].zfill(5*cipher.blockSize)[-16:]

print('\nTest key k = {:}'.format(k), end = ' ')
print( '(k_5 = {:}).'.format(hex(int(k5_bin,2))[2:].zfill(4)))

lApproxAllsk = [0]*(1+0xFF)
for pt in range(10000):
    ct = cipher.encrypt(pt, k)
    for pskb_4_8 in range(1 + 0xF):
        for pskb_12_16 in range(1 + 0xF):
            ct_4_8 = int(bin(ct)[2:].zfill(16)[4:8], 2)
            ct_12_16 = int(bin(ct)[2:].zfill(16)[12:16], 2)

            #xor ciphertext with subKey bits
            v_4_8, v_12_16 = ct_4_8^pskb_4_8, ct_12_16^pskb_12_16

            #run backwards through sbox
            u_4_8, u_12_16 = cipher.sbox[v_4_8], cipher.sbox[v_12_16]

            #Compute linear approximation: U_4,6 ^ U_4,8 ^ U_4,14 ^ U_4,16 ^ P_5 ^ P_7 ^ P_8
            lApprox = getNibbleBit(u_4_8, 1)^getNibbleBit(u_4_8, 3)^getNibbleBit(u_12_16, 1)^getNibbleBit(u_12_16, 3)
            lApprox = lApprox^getShortBit(pt, 4)^getShortBit(pt, 6)^getShortBit(pt, 7)
            lApproxAllsk[(pskb_4_8<<4)+pskb_12_16] += lApprox
            
attackResults = [fabs(lAprx - 5000)/10000.0 for lAprx in lApproxAllsk]

maxResult, maxIdx = 0,0
for rIdx, result in enumerate(attackResults):
    if result > maxResult:
        maxResult = result
        maxIdx = rIdx

print('Highest Bias is {:} for subKey bits {:}.'.format(maxResult, hex(maxIdx)[2:]))
print(attackResults)

      

