//
//  util.cpp
//  whiteboxAes
//
//  Created by bryce on 15/5/23.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#include <iostream>
#include "util.h"

/*
 * Multiplication in GF(2^8)
 * http://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Irreducible polynomial m(x) = x8 + x4 + x3 + x + 1
 */
BYTE gmult(BYTE a, BYTE b) {
    
    BYTE p = 0, i = 0, hbs = 0;
    
    for (i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        
        hbs = a & 0x80;
        a <<= 1;
        if (hbs) a ^= 0x1b; // 0000 0001 0001 1011
        b >>= 1;
    }
    
    return (BYTE)p;
}

using namespace std;

void printByte(BYTE b){
    char ch[3];
    ch[0] = (b - '\0')/16;
    ch[1] = (b - '\0')%16;
    ch[2] = 0;
    for(int i=0; i<2; i++)
    {
        if(ch[i] >= 0 && ch[i] <= 9)
            ch[i] = '0' + ch[i];
        else
            ch[i] = 'A' + ch[i] - 10;
    }
    cout << "0x" <<ch;
}

void matShow(const BYTE *out,int size){
    for(int j=0;j<size;j++){
        char ch[3];
        ch[0] = (out[j] - '\0')/16;
        ch[1] = (out[j] - '\0')%16;
        ch[2] = 0;
        for(int i=0; i<2; i++)
        {
            if(ch[i] >= 0 && ch[i] <= 9)
                ch[i] = '0' + ch[i];
            else
                ch[i] = 'A' + ch[i] - 10;
        }
        cout <<j <<":"<< ch << "\t ";
        if (j % 4 == 3)
            cout << endl;
    }
    cout << endl;
}
