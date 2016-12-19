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
# See README: Appendix, Figure 1 for working out



        
