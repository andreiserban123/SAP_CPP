#include "ex13Xor.h"
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    char opt[3];
    char mode[10];
    char fIn[200];
    char fOut[200];
    int i = 0, j = 0;
    int ch, numRead;

    unsigned char pass[ BUF_SIZE ]; 
    unsigned char buff[ BUF_SIZE ]; 

    unsigned char* buffW = (unsigned char*)malloc(( BUF_SIZE )*sizeof(unsigned char));
    
    unsigned char* iVector = (unsigned char*)malloc(( BUF_SIZE )*sizeof(unsigned char));
    for (i = 0; i < BUF_SIZE; i++) iVector[i] = 0x00; // or MD of the pass

    unsigned char* xorVector = (unsigned char*)malloc(( BUF_SIZE )*sizeof(unsigned char));

    if (argc < 4) {
        printf("\n Wrong number of parameters \n Example: UseCrypto.exe -e -ecb fSrc fDst");
        return 1;
    } else {
        strcpy(opt, argv[1]);
        strcpy(mode, argv[2]);
        strcpy(fIn, argv[3]);
        strcpy(fOut, argv[4]);

        printf("\n Enter pass please (16 chars):"); 
        /* Read in single line from "stdin": */
        for( i = 0; (i <  BUF_SIZE ) && ((ch = getchar()) != EOF) && (ch != '\n'); i++ )
            pass[i] = (unsigned char)ch;
        printf("\n pass received:%s", pass);

        FILE* fSrc, *fDst;
        fSrc = fopen(fIn, "rb");
        fDst = fopen(fOut, "wb");

        if (strcmp(opt, "-e") == 0) { 
            if (strcmp(mode, "-ecb") == 0) {
                while ((numRead = (int)fread(buff, 1, BUF_SIZE, fSrc)) > 0) {
                    buffW = encryptXor(buff, pass); 
                    fwrite(buffW, 1, numRead, fDst);
                    fflush(fDst);
                }
            } else {
                while ((numRead = (int)fread(buff, 1, BUF_SIZE, fSrc)) > 0) {
                    xorVector = xorArray(iVector, buff, numRead);
                    buffW = encryptXor(xorVector, pass); 
                    fwrite(buffW, 1, numRead, fDst);
                    fflush(fDst);
                    for (j = 0; j < numRead; j++) iVector[j] = buffW[j];
                }
            }
        } else { 
            if (strcmp(opt, "-d") == 0) {
                if (strcmp(mode, "-ecb") == 0) {
                    while ((numRead = (int)fread(buff, 1, BUF_SIZE, fSrc)) > 0) {
                        buffW = decryptXor(buff, pass);
                        fwrite(buffW, 1, numRead, fDst);
                        fflush(fDst);
                    }
                } else {
                    int kChunks = 0;
                    while ((numRead = (int)fread(buff, 1, BUF_SIZE, fSrc)) > 0) {
                        buffW = decryptXor(buff, pass);
                        if (kChunks == 0) {
                            for (j = 0; j < numRead; j++) iVector[j] = 0x00;
                        }
                        xorVector = xorArray(iVector, buffW, numRead);                         
                        fwrite(xorVector, 1, numRead, fDst);
                        fflush(fDst);
                        for (j = 0; j < numRead; j++) iVector[j] = buff[j];
                        kChunks++;
                    }
                }
            } else {
                printf("\n Unknown option \n Example: UseCrypto.exe -e -ecb fSrc fDst");
                return 2;
            }
        }
        fclose(fDst);
        fclose(fSrc);
    }

    return 0;
}