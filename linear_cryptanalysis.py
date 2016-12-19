#Linear cryptanalysis of a basic SPN cipher
#Try to determine linear expressions between input and output bits which have
#a linear probability bias. Randomly chosen bits would only satisfy the 
#expression with probability 0.5 (Matsui's Piling up Lemma)

from basic_SPN import *
from math import trunc
import itertools as it
import collections

#Build table of input values
sbox_in = ["".join(seq) for seq in it.product("01", repeat=4)]
#Build a table of output values
sbox_out = [ bin(sbox[int(seq,2)])[2:].zfill(4) for seq in sbox_in ]
#Build an ordered dictionary between input and output values
sbox_b = collections.OrderedDict(zip(sbox_in,sbox_out))
#Initialise LAT
probBias = [[0 for x in range(len(sbox_b))] for y in range(len(sbox_b))] 

print('Linear Approximation Table for basic cipher\'s sbox: ')
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

#print linear approximation table
for bias in probBias:
    for bia in bias:
        #trunc(((bia/16.0)-0.5)*16.0)
        print('{:d}'.format(bia-8).zfill(2), end=' ')
    print('')
    
# Constructing Linear Approximations for the Complete Cipher
# We concatenate linear approximations through multiple rounds
# e.g. Through 3 rounds
#      S_1,2: X1^X3^X4 = Y2, probBias = +4 (6,11 in LAT) (*1)
#      S_2,2:    X2 = Y2^Y4, probBias = -4 (4,5 in LAT)  (*2)
#      S_3,2:    X2 = Y2^Y4, probBias = -4               (*3)
#      S_3,4:    X2 = Y2^Y4, probBias = -4               (*4)
# Let U_i = sbox input in round i and |U_i| = block size (16 bits)
# and V_i = sbox output in round i and |V_i| = |U_i|
# then U_1 = P^K_1 where P = plaintext block and K_1 is round 1 subkey
#
# ... Now thinking about individual bits in the state from round to round:
#
# using (1) we get V_1,6 = sixth state bit in round 1 (from sbox S_1,2)
#                  V_1,6 = U_1,5 ^ U_1,7 ^ U_1,8 (Y2 = X1^X3^X4)
#                  V_1,6 = (P_5 ^ K_1,5) ^ (P_7 ^ K_1,7) ^ (P_8 ^ K_1,8) (*5)
# With probability bias = 4 => probability = (4+8)/16 = 0.75
#
# Using (2) in round 2: V_2,6 ^ V_2,8 = U_2,6 with Pr = (-4+8)/16 = 0.25 
# 
# Combining (5) & (6)
# V_2,6 ^ V_2,8 = (P_5 ^ K_1,5) ^ (P_7 ^ K_1,7) ^ (P_8 ^ K_1,8) (*6)
# (by Matsui's piling up lemma, incorrectly assuming independence)
# With probability 0.5 + 2*(0.75-0.5)*(0.25-0.5) = 3/8
#
# Using (3) for round 3: V_3,6 ^ V_3,8 = U_3,6 with Pr = 0.25
#                   and: V_3,14 ^ V_3,16 = U_3,14 with Pr = 0.25
#       (The permutation decides that we need this approximation)
#
# U_3,6 = V_2,6 ^ K_3,6 and U_3,14 = V_2,8 ^ K_3,14
# V_3,6 ^ V_3,8 ^ U_3,6 = 0 = V_3,14 ^ V_3,16 ^ U_3,14
# V_3,6 ^ V_3,8 ^ V_2,6 ^ K_3,6 = 0 = V_3,14 ^ V_3,16 ^ V_2,8 ^ K_3,14 (*7)
# Pr = 0.5 + 2*(0.25-0.5)*(0.25-0.5)
#
# Combining (6) and (7) to get an approximation for all-four sboxes:
# V_3,6 ^ V_3,8 ^ K_3,6 ^ V_3,14 ^ V_3,16 ^ K_3,14 ^ (P_5 ^ K_1,5) ^ (P_7 ^ K_1,7) ^ (P_8 ^ K_1,8) = 0
# additionally 
# U_4,6 = V_3,6 ^ K_4,6 and U_4,8 = V_3,14 ^ K_4,8 and U_4,14 = V_3,8 ^ K_4,14 and U_4,16 = V_3,16
# hence
# U_4,6 ^ U_4,8 ^ U_4,14 ^ U_4,14 ^ U_4,16 ^ P_5 ^ P_7 ^ P_8 ^ (Sum of K bits for all 4 rounds) = 0
# Pr = 0.5 + [2*(0.75-0.5)*(0.25-0.5)]^3 = 15/32
#
# Since sum over all K_bits == 1 | 0 we also know U_4,6 ^ U_4,8 ^ U_4,14 ^ U_4,14 ^ U_4,16 ^ P_5 ^ P_7 ^ P_8 = 0
# must hold with a probability of either 15/32 or 1-(15/32)
# ... in other words we have a linear approximation of rounds 1-3 which holds with a bias of magnitude 1/32. 





        
