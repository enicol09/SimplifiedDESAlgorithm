/** @file binary.c
 *  @brief This is a c file that helps in the implementation of Hw_1 - the SimplifiedDes.
 *         You can see all the function declarations in the h file  binary.h.
 *
 *  You can see below all the function implimentations.
 *
 *  @author Elia Nicolaou 1012334
 *  @version 1
 *  @bug No know bugs.
 *  @see SimplifiedDES.c, SIMP_DES.c
 */

#include "binary.h"

/** @brief given a value returns the binary form of the value.
 * @param the given value
 * @bin  : the binary form of the values
 */
void makebinary(int value, char *bin){
  switch (value) {

    case 0:
    strcpy(bin,"00");
    break;

    case 1:
    strcpy(bin,"01");
    break;

    case 2:
    strcpy(bin,"10");
    break;

    case 3:
    strcpy(bin,"11");
    break;
  }

}
