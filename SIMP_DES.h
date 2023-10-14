/** @file simp_des.h
 *  @brief This is a header file that helps in the implementation of Hw_1 - the SimplifiedDes.
 *         You can see all the function implementations in the c file SIMP_DES.c.Overall,
 *         this h file contains the function declarations that they are need in order to implement
 *         the SIMPLIFIED DES cryptography algorithm.
 *
 *  You can see below all the function exmplanations.
 *
 *  @author Elia Nicolaou 1012334
 *  @version 1
 *  @bug No know bugs.
 *  @see SimplifiedDES.c, SIMP_DES.c
 */

//define the header files.

#ifndef SIMP_DES_H
#define SIMP_DES_H

//--------------------------------------------------//

//include libraries.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include "binary.h"

//--------------------------------------------------//

//=====================DEFINE CONSTANTS =======================//

#define DEBUG true
#define BIT8 8
#define BIT10 10

//===================== DEFINE ARRAYS=======================//

//initial permutation & reverse permutation & expansion permutation
static const int IP[] = {1, 5, 2, 0, 3, 7, 4, 6};
static const int IPR[] = {3, 0, 2, 4, 6, 1, 7, 5};
static const int EP[]= {3,0,1,2,1,2,3,0};

//sbox0 && sbox1
static const int s0_box[][4] = {{1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2}};
static const int s1_box[][4] = {{0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3}};

//P4,P8,P10
static const int P10[] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
static const int P8[] = {5, 2, 6, 3, 7, 4, 9, 8};
static const int P4[] = { 1, 3, 2, 0};

//switching operation
static const int SW[8] = { 4,5,6,7,0,1,2,3};

//xorvalues
static const char xorvalues[] = {'0','1'};

//================== FUNCTION DECLARATIONS =======================//

//==================      KEY FUNCTIONS    =======================//

/** @brief This function is being used for the "key scheduling" part of the algorithm.
 *         In our case we have to produce only two keys (K1,k2) so the function calls another
 *         2 functions in order to produce the keys.
 *
 * @param  key the given key of 10 bits
 */
void keyScheduling(char *key);

/** @brief This function is being used from the function k1Scheduling.It's purpose is to pass
 *         the given key through the P10 permutation (see the P10 permutation at the arrays above).
 *         The P10 permutation is only used once.
 *
 * @param  key the given key from that we use for encryption of 10 bits.
 */
void keyScheduling10bit(char *key);

/** @brief This function is being used for operating left shift on a given key.
 *          What leftShift does is to  break the key into two subkeys consisting of the
 *          first 5 and last 5 bits and shift each subkey to the left by 1
 *
 * @param  key that must be shifted.
 */
void leftShift(char *tempKey);

/** @brief This function is being called after the shifting operation.It's purpose is to pass
 *         the shifted key through the P8 permutation (see the P8 permutation at the arrays above).
 *         The P10 permutation is used one time for the first key (k1) and another time for the second key(k2)
 *
 * @param  key that must be passed through the P8 permutation.
 * @param  val determinates which key is going to be passed through the P8 permutation. 1 = k1 , 2 = k2
 */
void keyScheduling8bit (char *tempKey, int val);

/** @brief This function is being called by the keyScheduling function in order to create the k1 - subkey K1.
 *  The function calls the below functions in order to crete k1 :
 *  1.keyScheduling10bit
 *  2. leftShift
 *  3.keyScheduling8bit with val = 2
 *
 * @param  key the given key from the user.
 */
void k1Scheduling(char *key);

/** @brief This function is being called by the keyScheduling function in order to create the k2 - subkey K2.
 *  The function calls the below functions in order to crete k2 :
 *  1. leftShift
 *  2. leftShift
 *  3.keyScheduling8bit with val = 2
 *
 * @param  key the given key from the user.
 */
void k2Scheduling(char *key);

//encryption main function
/** @brief This is the most important function  as it moves through all the basic steps
 * for the encryption of the plaintext.
 *
 * @param key: the given key from the user.
 * @param plaintext : the given plaintext that is going to be encrypted.
 */
void Encryption(char *plaintext, char *key);

/** @brief This function is being used from the function encryption.It's purpose is to pass
 *         the given key through the Initial permutation  IP. initialPermutation is the first step
 *         that takes place for the encryption (see the IP permutation at the arrays above).
 *         The IP permutation is only used once.
 *
 * @param plaintext : the given plaintext that is going to be encrypted.
 */
void initialPermutation(char *plaintext);

/** @brief This function is being used from the function encryption.It's purpose is to pass
 *         the given key through the externalPermuatation permutation IPR. It is the reverse of initialPermutation
 *         and is the last step that takes place for the encryption (see the IPR permutation at the arrays above).
 *         The IPR permutation is only used once.
 *
 * @param cipher : the given until know encrypted plaintext.
 */
void externalPermuatation(char *cipher);

/** @brief First of all I have to explain that the name feistelNetwork is not accurate, I took it from
 *  the basic DES. Although it does the operations that needed for the encryption.
 *  Those operations are: 1. division , 2. Expansion ,3.xor , 4.division to sboxes 5.sboxes operation 6.p4permutation 7.xor 8.merge
 *
 * @param cipher : the going to be encrypted plaintext
 * @param key : the current subkey
 */
void feistelNetwork(char *cipher,char *key);

/** @brief xor function performs the xor operation.
 *
 * @param input = the first variable of xor.
 * @param input2 = the second variable of xor.
 */
void xor(char *input, char *input2);

/** @brief This function is being used by the encryption function.It's purpose is to do the switching operation that occurs between the
 *         first part of the encryption ( the one that uses the k1 ) and the second (k20.
 *
 * @param cipher = the cipher that must go through the switching.
 */
void switching(char *cipher);

/** @brief This function is being used in the function feistelNetwork (see definition).It's purpose is to pass
 *         the 4 bits from the s0 and s1 boxes through the p4permutation (see the P4 permutation at the arrays above).
 *
 * @param sbox : sbox contains the 2 bits from the S0box and other two from the S1box
 */
void p4permutation(char *sbox);

/** @brief This function performs the expansionPermutation after the division of the blocks and boxes.
 *  @param block : the box/block that needs to be expand through the expansionPermutation
 */
void expansion(char *block);

//division
/** @brief This function performs the division into two blocks at the begging of the "feistelNetwork".
 *  @param cipher = the cipher that must be divide in 2 blocks.
 */
void divide2blocks(char *cipher);

/** @brief This function performs the division into two blocks before they go through the sboxes.
 *  In addition it creates 2 sub-blocks of the Cipher. S0 - will be for S0box and S1 - will be for S1Box.
 *  @param cipher = the cipher that must be divide in 2 sub-blocks.
 */
void divide2blocksAfter(char *cipher);

//print
/** @brief This is function prints the final encrypted plaintext.
 */
void printCipher();

//deallocate
/** @brief This is a helpful destruction function that is being called
 *  in order to deallocate certain mallocs.
 */
void deallocate();

/** @brief This is a helpful destruction function that is being called after
 *  the opperation of the feistelNetwork in order to deallocate certain mallocs.
 */
void deallocateFeistel();
#endif
