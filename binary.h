/** @file binary.h
 *  @brief This is a header file that helps in the implementation of Hw_1 - the SimplifiedDes.
 *         You can see all the function implementations in the c file  binary.c.
 *
 *  You can see below all the function exmplanations.
 *
 *  @author Elia Nicolaou 1012334
 *  @version 1
 *  @bug No know bugs.
 *  @see SimplifiedDES.c, SIMP_DES.c
 */

#ifndef BINARY_H
#define BINARY_H

//--------------------------------------------------//

//include libraries
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>

/** @brief given a value returns the binary form of the value.
 * @param the given value
 * @bin  : the binary form of the values
 */
void makebinary(int value, char *bin);

#endif
