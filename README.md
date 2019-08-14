A basic Substitution-Permutation Network (SPN) cipher and it's cryptanalysis 
using the linear method. Implemented by following 'A Tutorial on Linear 
and Differential Cryptanalysis' by Howard M. Heys. This project has been 
developed using Python 3.7.3.

The main files in this project are as follows

1. basic_SPN.py - Implements the basic SPN cipher including key generation, 
encryption and decryption methods. The cipher takes as input a 16-bit input
block and has 4 rounds, each comprising substitution, transposition and key 
mixing. Running this file will encrypt 10,000 incremental values using a 
random key. The ciphertexts are written to file in the 'testData' directory
in CSV format.

2. linear_cryptanalysis - Attacks the basic SPN cipher using linear cryptanalysis. 
We derive a linear approximation for the first three rounds that we then
use to derive some of the key bits. Running this file will print the Linear Approximation
Table for the simple SPN S-box, generate a random key and then will recover 8~bits 
of the key using linear cryptanalytic techniques.

# Constructing linear approximations for the complete cipher

To do this we concatenate linear approximations through multiple rounds.
Linear approximations are given by the linear approximation table
which is derived by testing all possible linear relationships between
input and output bits for a given sbox.

e.g. Through 3 rounds
      S_1,2: X1⊕X3⊕X4 = Y2, probBias = +4 (6,11 in LAT) (*1)
      S_2,2:    X2 = Y2⊕Y4, probBias = -4 (4,5 in LAT)  (*2)
      S_3,2:    X2 = Y2⊕Y4, probBias = -4               (*3)
      S_3,4:    X2 = Y2⊕Y4, probBias = -4               (*4)
      
Let U_i = sbox input in round i and |U_i| = block size (16 bits),
and V_i = sbox output in round i and |V_i| = |U_i|,
then U_1 = P⊕K_1 where P = plaintext block and K_1 is round 1 subkey

Now thinking about individual bits in the state from round to round:

Using equation (1) we get V_1,6 = sixth state bit in round 1 (from sbox S_1,2)
                          V_1,6 = U_1,5 ⊕ U_1,7 ⊕ U_1,8 (Y2 = X1⊕X3⊕X4)
                          V_1,6 = (P_5 ⊕ K_1,5) ⊕ (P_7 ⊕ K_1,7) ⊕ (P_8 ⊕ K_1,8) (*5)
With probability bias = 4 => probability = (4+8)/16 = 0.75

Using equation (2) in round 2: V_2,6 ⊕ V_2,8 = U_2,6 with Pr = (-4+8)/16 = 0.25 
 
Combining (5) & (6)
V_2,6 ⊕ V_2,8 = (P_5 ⊕ K_1,5) ⊕ (P_7 ⊕ K_1,7) ⊕ (P_8 ⊕ K_1,8) (*6)
By Matsui's piling up lemma, incorrectly assuming independence)
With probability 0.5 + 2*(0.75-0.5)*(0.25-0.5) = 3/8

Using (3) for round 3: V_3,6 ⊕ V_3,8 = U_3,6 with Pr = 0.25
                  and: V_3,14 ⊕ V_3,16 = U_3,14 with Pr = 0.25
      (The permutation decides that we need this approximation)

U_3,6 = V_2,6 ⊕ K_3,6 and U_3,14 = V_2,8 ⊕ K_3,14
V_3,6 ⊕ V_3,8 ⊕ U_3,6 = 0 = V_3,14 ⊕ V_3,16 ⊕ U_3,14

Therefore:
V_3,6 ⊕ V_3,8 ⊕ V_2,6 ⊕ K_3,6 = 0 = V_3,14 ⊕ V_3,16 ⊕ V_2,8 ⊕ K_3,14 (*7)
with Pr = 0.5 + 2*(0.25-0.5)*(0.25-0.5)

Combining (6) and (7) to get an approximation for all-four sboxes:
V_3,6 ⊕ V_3,8 ⊕ K_3,6 ⊕ V_3,14 ⊕ V_3,16 ⊕ K_3,14 ⊕ (P_5 ⊕ K_1,5) ⊕ (P_7 ⊕ K_1,7) ⊕ (P_8 ⊕ K_1,8) = 0
additionally,
U_4,6 = V_3,6 ⊕ K_4,6 and U_4,8 = V_3,14 ⊕ K_4,8 and U_4,14 = V_3,8 ⊕ K_4,14 and U_4,16 = V_3,16

therefore:
U_4,6 ⊕ U_4,8 ⊕ U_4,14 ⊕ U_4,14 ⊕ U_4,16 ⊕ P_5 ⊕ P_7 ⊕ P_8 ⊕ (Sum of K bits for all 4 rounds) = 0
Pr = 0.5 + [2*(0.75-0.5)*(0.25-0.5)]⊕3 = 15/32

Since sum over all K_bits == 1 | 0 we also know U_4,6 ⊕ U_4,8 ⊕ U_4,14 ⊕ U_4,14 ⊕ U_4,16 ⊕ P_5 ⊕ P_7 ⊕ P_8 = 0
must hold with a probability of either 15/32 or 1-(15/32)

Thus we have a linear approximation of rounds 1-3 which holds with a bias of magnitude 1/32. 

Using this approximation it is possible to it is possible to extract bits from subkey K_5.
In particular, we partially decrypt the last round of the cipher. For all possible values
0...255 of the target subkey, we compute the XOR with the corresponding ciphertext bits and
then run the result backwards through the S-Boxes. This is done for all know plaintext-ciphertext
pairs and a count is kept for each potential subkey value. The count is incremented when
the linear approximation holds for this subkey. Since an incorrect subkey guess most likely
results in a random guess of the S-Box input bits, the correct subkey guess can be identified
as the key value with the highest counter value. 

