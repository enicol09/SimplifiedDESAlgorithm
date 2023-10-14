/** @file simp_des.c
 *  @brief This is the c file that does the implementation of Hw_1 - the SimplifiedDes.
 *         It contains all the function implementations as they are declared at h file SIMP_DES.h .
 *         Overall, this c file contains the function implementations that they are need in order to implement
 *         the SIMPLIFIED DES cryptography algorithm.
 *
 *  You can see below all the function exmplanations.
 *
 *  @author Elia Nicolaou 1012334
 *  @version 1
 *  @bug No know bugs.
 *  @see SimplifiedDES.c, SIMP_DES.h
 */

#include "SIMP_DES.h"
#include "binary.h"

//GLOBAL VARIABLES
//keys
char *k1;
char *k2;
char *tempKey; //tempKey

//box
char *sbox;

//makebinary
char *bin;
//cipher
char *cipher;

//block
char *block1; //left
char *block2; //right

//after block
char *s0;
char *s1;
int s0int;
int s1int;
//======================= DEALLOCATIONS =========================================//
//deallocate
/** @brief This is a helpful destruction function that is being called
 *  in order to deallocate certain mallocs.
 */
void deallocate(){
  free(k1);
  free(k2);
  free(tempKey);
  free(cipher);
}

/** @brief This is a helpful destruction function that is being called after
 *  the opperation of the feistelNetwork in order to deallocate certain mallocs.
 */
void deallocateFeistel(){
       free(sbox);
       free(block1);
       free(block2);
       free(s0);
       free(s1);
}
//======================= ENCRYPTION FUNCTIONS ==================================//

//encryption main function
/** @brief This is the most important function  as it moves through all the basic steps
 * for the encryption of the plaintext.
 *
 * @param key: the given key from the user.
 * @param plaintext : the given plaintext that is going to be encrypted.
 */
void Encryption(char *plaintext, char *key){
  //malloc
  cipher = (char *) malloc(9);

  initialPermutation(plaintext);
  feistelNetwork(cipher,k1); //k1 //firstpart
  switching(cipher);
  feistelNetwork(cipher,k2); //k2 //secondpart
  externalPermuatation(cipher);
  //print the result
  printCipher();
  deallocate();
}
/** @brief This function is being used from the function encryption.It's purpose is to pass
 *         the given key through the externalPermuatation permutation IPR. It is the reverse of initialPermutation
 *         and is the last step that takes place for the encryption (see the IPR permutation at the arrays above).
 *         The IPR permutation is only used once.
 *
 * @param cipher : the given until know encrypted plaintext.
 */
void externalPermuatation(char *cipher){
int i;
char *temp;
temp = (char *) malloc(9);

  for(i=0; i< BIT8; i++){
    int c = IPR[i];
    temp[i] = cipher[c];}
    strcpy(cipher,temp);
    free(temp);
}

//print
/** @brief This is function prints the final encrypted plaintext.
 */
void printCipher(){
 printf("%s \n",cipher);
}

/** @brief This function is being used from the function encryption.It's purpose is to pass
 *         the given key through the Initial permutation  IP. initialPermutation is the first step
 *         that takes place for the encryption (see the IP permutation at the arrays above).
 *         The IP permutation is only used once.
 *
 * @param plaintext : the given plaintext that is going to be encrypted.
 */
void initialPermutation(char *plaintext){
  int i;
  for(i=0; i< BIT8; i++){
    int c = IP[i];
    cipher[i] = plaintext[c];  }

if(DEBUG)
  printf("\nPlaintext after initialPermutation : %s \n", cipher);
}

/** @brief This function is being used by the encryption function.It's purpose is to do the switching operation that occurs between the
 *         first part of the encryption ( the one that uses the k1 ) and the second (k20.
 *
 * @param cipher = the cipher that must go through the switching.
 */
void switching(char *cipher){
  int i;
  char *temp;
  temp = (char *) malloc(9);

  for(i=0;i< BIT8;i++){
    temp[i]=cipher[SW[i]];
  }
  strcpy(cipher,temp);
  free(temp);
  if(DEBUG)
    printf("\n Cipher after switching : %s \n" , cipher);
}

//------------FEISTEL NETWORK ----------------------------//

/** @brief First of all I have to explain that the name feistelNetwork is not accurate, I took it from
 *  the basic DES. Although it does the operations that needed for the encryption.
 *  Those operations are: 1. division , 2. Expansion ,3.xor , 4.division to sboxes 5.sboxes operation 6.p4permutation 7.xor 8.merge
 *
 * @param cipher : the going to be encrypted plaintext
 * @param key : the current subkey
 */
void feistelNetwork(char *cipher,char *key){

       block1 = (char *) malloc(5);
       block2 = (char *) malloc(5);

       divide2blocks(cipher); //CHECKED
       expansion(block2); //checked

       if(DEBUG)
       printf("xored with k and cipher: %s , %s",key , cipher);
       xor(cipher,key); //checked
       if(DEBUG)
       printf("Plaintext after xored with k1: %s",cipher);


       s0 = (char *) malloc(5);
       s1 = (char *) malloc(5);
       //sbox1 && sbox2
       divide2blocksAfter(cipher); //checked

       //sbox0 - akries row / esoterika column
       int row = 0;
       int clm = 0;
       int r=1;
       int c=1;
       int i;

       for(i=0;i<4;i++){
         if((i == 0 || i==3)){
           if(s0[i] == '1')
           row += pow(2,r);
           r--;
           }
         else if((i == 1 || i==2)) {
            if(s0[i] == '1') {
            clm += pow(2,c);}
            c--;
          }

       }


       s0int = s0_box[row][clm];

       //sbox1- akries row / esoterika column
       row = 0;
       clm = 0;
       r=1;
       c=1;

       for(i=0;i<4;i++){
         if((i == 0 || i==3)){
           if(s1[i] == '1')
           row += pow(2,r);
           r--;
           }
         else if((i == 1 || i==2)) {
            if(s1[i] == '1') {
            clm += pow(2,c);}
            c--;
          }

       }

       s1int = s1_box[row][clm]; //s1
       bin = (char *) malloc(3);
       makebinary(s0int,bin);
       sbox = (char *) malloc(5);

       if(DEBUG)
       printf("\nSBOX0 BINARY %s ",bin);
       strcpy(sbox,bin);

       free(bin);
       bin = (char *) malloc(3);
       makebinary(s1int,bin);
       if(DEBUG)
       printf("\nSBOX1 BINARY %s ",bin);
       strcat(sbox,bin); //merging

       free(bin);

       if(DEBUG)
       printf("\nMerged xored %s ",sbox);

       p4permutation(sbox); //done

       xor(block1,cipher);
       strcat(cipher,block2);

         if(DEBUG)
         printf("\n Plaintext after merged: %s",cipher);


       deallocateFeistel();

}
/** @brief This function is being used in the function feistelNetwork (see definition).It's purpose is to pass
 *         the 4 bits from the s0 and s1 boxes through the p4permutation (see the P4 permutation at the arrays above).
 *
 * @param sbox : sbox contains the 2 bits from the S0box and other two from the S1box
 */
void p4permutation(char *sbox){
  int i;
  char *sbox2;
  sbox2 = (char *) malloc(5);

  for (i=0;i<4;i++){
    sbox2[i]= sbox[P4[i]];
  }

  if(DEBUG)
  printf("\nPermutation P4 done %s:",sbox2);

  strcpy(cipher,sbox2);

  if(DEBUG)
  printf("\nPermutationP4: %s",cipher);

  free(sbox2);
}

/** @brief This function performs the expansionPermutation after the division of the blocks and boxes.
 *  @param block : the box/block that needs to be expand through the expansionPermutation
 */
void expansion(char *block){
  int i;
  for(i=0; i< BIT8 ; i++){
    int c = EP[i];
    cipher[i] = block[c];  }

  if(DEBUG)
  printf("\nCipher after expansionPermutation : %s \n", cipher);

}

//division
/** @brief This function performs the division into two blocks at the begging of the "feistelNetwork".
 *  @param cipher = the cipher that must be divide in 2 blocks.
 */
void divide2blocks(char *cipher){
  int i;
  for(i=0;i<4;i++){
    block1[i] = cipher[i];
  }

int j = 0;
  for(i=4;i<BIT8;i++){
    block2[j] = cipher[i];
    j++;
    }

  if(DEBUG) {
  printf("\nBLOCK1 after 1st division : %s", block1);
  printf("\nBLOCK2 after 1st division : %s", block2); }

}

/** @brief This function performs the division into two blocks before they go through the sboxes.
 *  In addition it creates 2 sub-blocks of the Cipher. S0 - will be for S0box and S1 - will be for S1Box.
 *  @param cipher = the cipher that must be divide in 2 sub-blocks.
 */
void divide2blocksAfter(char *cipher){
  int i;
  for(i=0;i<4;i++){
    s0[i] = cipher[i];
  }
int j;
  j=0;
  for(i=4;i<8;i++){
    s1[j] = cipher[i];
    j++;
  }

  if(DEBUG){
  printf("\nBLOCK1 after 2st division (after xored) : %s", s0);
  printf("\nBLOCK2 after 2st division (after xored) : %s", s1);}
}

/** @brief xor function performs the xor operation.
 *
 * @param input = the first variable of xor.
 * @param input2 = the second variable of xor.
 */
void xor(char *input, char *input2){
  //for all bits check
  int i;

  for(i=0;i<strlen(input);i++){
    if(input[i] == input2[i]){
      cipher[i] = xorvalues[0];
    }
    else{
      cipher[i] = xorvalues[1];
    }
  }
}

//===============================================================================//
//========================KEY SCHEDULING FUNCTIONS ==============================//

/** @brief This function is being called by the keyScheduling function in order to create the k1 - subkey K1.
 *  The function calls the below functions in order to crete k1 :
 *  1.keyScheduling10bit
 *  2. leftShift
 *  3.keyScheduling8bit with val = 2
 *
 * @param  key the given key from the user.
 */
 void k1Scheduling(char *key){

   keyScheduling10bit(key);

   if(DEBUG)
   printf("\nKey after 10BIT Permutation rearrange %s", tempKey );

   leftShift(tempKey);

   if(DEBUG)
   printf("\nKey after LeftShift %s", tempKey );

   keyScheduling8bit(tempKey, 1);

   if(DEBUG)
    printf("\nKey K1: %s", k1 );
 }

 /** @brief This function is being called by the keyScheduling function in order to create the k2 - subkey K2.
  *  The function calls the below functions in order to crete k2 :
  *  1. leftShift
  *  2. leftShift
  *  3.keyScheduling8bit with val = 2
  *
  * @param  key the given key from the user.
  */
 void k2Scheduling(char *key){

     leftShift(tempKey);
     if(DEBUG)
     printf("\nKey after leftShift %s", tempKey );

     leftShift(tempKey);

     if(DEBUG)
     printf("\nKey after leftShift %s", tempKey );

     keyScheduling8bit(tempKey, 2);

     if(DEBUG)
     printf("\nKey K2: %s \n", k2 );


     if(DEBUG)
     printf("\n ========== KEYS FOUND ========== ");
 }

 /** @brief This function is being used for the "key scheduling" part of the algorithm.
  *         In our case we have to produce only two keys (K1,k2) so the function calls another
  *         2 functions in order to produce the keys.
  *
  * @param  key the given key of 10 bits
  */
 void keyScheduling(char *key){

    k1 = (char *) malloc(9);
    k2 = (char *) malloc(9);
    tempKey = (char *) malloc(11);
    k1Scheduling(key);
    k2Scheduling(tempKey);

 }

 /** @brief This function is being called after the shifting operation.It's purpose is to pass
  *         the shifted key through the P8 permutation (see the P8 permutation at the arrays above).
  *         The P10 permutation is used one time for the first key (k1) and another time for the second key(k2)
  *
  * @param  key that must be passed through the P8 permutation.
  * @param  val determinates which key is going to be passed through the P8 permutation. 1 = k1 , 2 = k2
  */
 void keyScheduling8bit (char *tempKey, int val){
 	int i;
 	if (val == 1) {
 		for (i = 0; i < BIT8; i++){
      int c = P8[i];
      k1[i] = tempKey[c];}
 	}

 	else if(val == 2) {
 		for (i = 0; i < BIT8; i++){
     int c = P8[i];
      k2[i] = tempKey[c];}
 	}
 }

 /** @brief This function is being used from the function k1Scheduling.It's purpose is to pass
  *         the given key through the P10 permutation (see the P10 permutation at the arrays above).
  *         The P10 permutation is only used once.
  *
  * @param  key the given key from that we use for encryption of 10 bits.
  */
 void keyScheduling10bit(char *key) {
 	int cnt;
 	for (cnt = 0; cnt < BIT10; cnt++)
        tempKey[cnt] = key[P10[cnt]];
 }
 /** @brief This function is being used for operating left shift on a given key.
  *          What leftShift does is to  break the key into two subkeys consisting of the
  *          first 5 and last 5 bits and shift each subkey to the left by 1
  *
  * @param  key that must be shifted.
  */
 void leftShift(char *tempKey){
 	char temp = tempKey[0];
 	int i;
  for (i = 0; i < 5; i++) {
 		tempKey[i] = tempKey[i+1];
 	}

 	tempKey[4] = temp;
 	temp = tempKey[5];

 	for (i = 5 ; i < BIT10; i++) {
 		tempKey[i] = tempKey[i+1];
 	}
 	tempKey[9] = temp;
 }

//=====================================================================//
