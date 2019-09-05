#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 16 18:22:05 2019

@author: dlesnoff
"""
#Files needed
sboxFilePath = 'Sbox.txt'


# Permutations declarations
## Initial Permutation
IP = [58,50,42,34,26,18,10,2,
      60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,
      64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,
      59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,
      63,55,47,39,31,23,15,7]

## Inverse of IP
IP_1 = [0 for _ in range(64)]
for i in range(len(IP)):
    IP_1[IP[i]-1]= i+1

## Permutation Choice
PC1_C =[57,49,41,33,25,17,9,
       1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,
       19,11,3,60,52,44,36]
	
PC1_D =[63, 55, 47, 39, 31, 23, 15,
       7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,
       21,13,5,28,20,12,4]
PC1 = PC1_C + PC1_D

PC2 = [14,17,11,24,1,5,
       3,28,15,6,21,10,
       23,19,12,4,26,8,
       16,7,27,20,13,2,
       41,52,31,37,47,55,
       30,40,51,45,33,48,
       44,49,39,56,34,53,
       46,42,50,36,29,32]

Expansion = [32,1,2,3,4,5,
            4,5,6,7,8,9,
            8,9,10,11,12,13,
            12,13,14,15,16,17,
            16,17,18,19,20,21,
            20,21,22,23,24,25,
            24,25,26,27,28,29,
            28,29,30,31,32,1]

Pbox = [16,7,20,21,29,12,28,17,
        1,15,23,26,5,18,31,10,
        2,8,24,14,32,27,3,9,
        19,13,30,6,22,11,4,25]
Pbox_1 = [0 for _ in range(len(Pbox))]
for i in range(len(Pbox)):
    Pbox_1[Pbox[i]-1]=i+1

R1 = [ (i+2)%28 for i in range(28)] # Index left shift of 1 bit
R2 = [(i+3)%28 for i in range(28)] # Index left shift of 2 bits

def videur(Pile,li):
    """
    Lit un nombre dans Pile et le passe dans la liste.
    """
    s=''
    while Pile != []:
        s+=Pile.pop()
    li.append(int(s[::-1]))

#Initialize S with the 8 S-boxes.
with open(sboxFilePath,'r') as f:
    S=[]
    for box in range(8):
        S.append([])
        for i in range(5):
            l=str(f.readline())
            if i>0:
                l=l.replace(" \t",",")[:-1]
                #Conversion of string to list
                Pile,temp = [],[]
                for c in l:
                    if c != ',':
                        Pile.append(c)
                    else:
                        videur(Pile,temp)
                videur(Pile,temp)#dernier élément non suivi d'une virgule
                S[box].append(temp)


# DES Functions definitions

def permutation(bin_num,liste):
    b = bin_num[2:]
    assert len(b) == len(liste)
    out = '0b'
    for i in range(len(liste)):
        out += b[liste[i]-1]
    return out

def XOR(L,R):
    out = '0b'
    for x, y in zip(L[2:], R[2:]):
        out += str(int(bool(int(x)) ^ bool(int(y)))) 
    return out

def remove_parity_bits(Key,Perm = PC1): # Key in hex representation w/ parity bits
    out = '0b'
    Key = bin(int(Key,16))[2:] # hex -> bin
    Key ='0'*(64-len(Key))+Key
    assert len(Key) == 64 # Test, 64
    for i in range(len(Perm)):
        out += Key[Perm[i]-1] # Permutation removes parity bits
    return out

def select_bits_for_subkey(byte,Perm=PC2):
    b = byte[2:]
    out = '0b'
    for i in range(len(Perm)):
        out += b[Perm[i]-1]
    return out

def key_schedule(Key): # 64 bits w/ 8 parity bits
    v = [1,2,9,16]
    K = [] # Sub-Keys list
    Key = remove_parity_bits(Key)
    C,D = Key[:30],'0b' + Key[30:] # 28 bit halves
    for i in range(16):
        if i+1 in v:
            C = permutation(C,R1)
            D = permutation(D,R1)
        else:
            C = permutation(C,R2)
            D = permutation(D,R2)
        K.append(select_bits_for_subkey(C+D[2:],PC2))
    return K

def expansion(byte,L=Expansion):
    """
    Expand a string of 32 bits length into a 48 bits one.
    """
    b = byte[2:] # remove the '0b'
    assert len(b) == 32
    out ='0b'
    for i in range(len(L)):
        out += b[L[i]-1]
    return out

def reduction(byte,L=S):
    """
    Reduce with the S-boxes functions.
    """
    b = byte[2:]
    assert len(b) == 48
    out = '0b'
    for i in range(8):
        B = b[i*6:(i+1)*6]
        r = 2*int(B[0]) + int(B[-1])
        c = int(B[1:5],2)
        t = bin(S[i][r][c])[2:]
        out += '0'*(4-len(t))+t
    return out

def f(byte,subKey):
    """
    Cryptographic function
    """
    e = expansion(byte)
    X = XOR(e,subKey)
    res = reduction(X)
    return permutation(res,Pbox)

def DES(plaintext,key):
    plaintext = bin(int(plaintext,16)) # conversion hexa -> bin
    K = key_schedule(key)
    temp = permutation(plaintext,IP)
    L,R = temp[:34],'0b' + temp[34:] # L_0,R_0
    X = XOR(L,R)
    for i in range(15): # 15 first rounds
        F = f(R,K[i])
        X = XOR(L,F)
        L,R = R,X # Swap
    F = f(R,K[15])
    X = XOR(L,F)
    L,R = X,R # No swap
    cypher = permutation(L+R[2:],IP_1)
    return hex(int(cypher,2))
