/** @file SimplifiedDES.c
 *   @brief This is the main function of the implementation of Simplidied DES in C programming language.
 *   Simplified DES is a cipher very similar to the original DES. The cipher is much simpler,
 *   but the structure (i.e., the Feistel network) is essentially the one used in DES. Instead of 16 rounds, there are only 2, and
 *   the block size is only 8 bits. In addition,
 *   there are only 2 S-box structures.
 *
 *  @author Elia Nicolaou 1012334
 *  @version 1
 *  @bug No know bugs.
 *
 */

 #include "SIMP_DES.h"

//sample
//Sample values
 char SAMPLE[] = {'0','1','0','1','0','0','0','1'};
 char KEY[11] = {'0','1','0','1','0','0','1','1','0','0'};
//have to check the argc/argv values though

 int main (int argc, char const *argv[]) {

 int size = argc - 1;
 printf("size is %i " , size);

   if (size == 0) {
       printf ("\n --- This is mode 1 - we use the sample valus as they are given in the exercise!");
       printf ("\n ->---------------------------------------------------------------------------<-");
       if(DEBUG) {
       printf ("\nThe plaintext that is going to be encrypted is: %s " ,SAMPLE);
       printf ("\nThe key that is being used for encryption is: %s " ,KEY); }

       if(DEBUG)
       printf("\n \n ======== FINDING KEYS ========  \n");
       keyScheduling(KEY);

       if(DEBUG)
       printf("\n \n ======== S========  \n");
       Encryption(SAMPLE,KEY);

     }

     else {

       char *plaintext;
       char *key;

       int size1 = strlen(argv[1]);
       int size2 = strlen(argv[2]);

       plaintext = (char *) malloc(size1);
       key = (char *) malloc(size2);

       strcpy(plaintext,argv[1]);
       strcpy(key,argv[2]);

       if(DEBUG) {
       printf ("\n The plaintext that is going to be encrypted is: %s " , plaintext);
       printf ("\n The key that is being used for encryption is: %s " , key); }

       keyScheduling(key);
       Encryption(plaintext,key);

      free(plaintext);
      free(key);

     }

 }
