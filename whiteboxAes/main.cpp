//
//  main.cpp
//  whiteboxAes
//
//  Created by bryce on 15/5/23.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#include <iostream>
#include <unistd.h>
#include <time.h>
#include <stdio.h>

// NTL dependencies
#include <NTL/GF2.h>
#include <NTL/mat_GF2.h>

#include "aes.h"
#include "waes.h"
#include "waesGenerator.h"
#include "bijection.h"

using namespace std;


template<keyLength L>
void compare(BYTE *key,W128b &in){
    
    clock_t t;
    BYTE aesOut[16];
    BYTE waesOut[16];
    
    
    AES<L> aes(key);
    t = clock();
    aes.encryptBlock(in.B, aesOut);
    t = clock() - t;
    printf ("AES %ld clicks (%f seconds).\n",t,((float)t)/CLOCKS_PER_SEC);
    
    
    WAES<L> waes(key);
    t = clock();
    waes.encryptBlock(in,waesOut);
    t = clock() - t;
    printf ("WAES %ld clicks (%f seconds).\n",t,((float)t)/CLOCKS_PER_SEC);
    
    
    bool flag = true;
    for(int j=0;j<16;j++){
        printByte(waesOut[j]);
        cout << ",";
        printByte(aesOut[j]);
        cout << endl;
        if (waesOut[j] != aesOut[j]) {
            flag = false;
        }
    }
    if (flag)
        cout << "same" << endl;
    else
        cout << "not same" << endl;
}




int main(int argc, const char * argv[]) {
    
    cout << "AES test:"<<endl;
    
    BYTE key[] ={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    BYTE key2[] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b};
    W128b input = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
   
    //BYTE correct[17] = {0x39,0x25,0x84,0x1D,0x02,0xDC,0x09,0xFB,0xDC,0x11,0x85,0x97,0x19,0x6A,0x0B,0x32};
    
    //BYTE b1[16];
    //BYTE b2[16];
    compare<key128>(key, input);
    compare<key192>(key2, input);
    
    //generateRandomBijectionT(b1, b2, 16, 1);
    //matShow(b1);
    //matShow(b2);
    
//    NTL::mat_GF2 m1, m2 ,m3, m4;
//    m1 = randomMixingBijection(m1, 4);
//    m2 = randomMixingBijection(m2, 4);
//    m3 = randomMixingBijection(m3, 4);
//    WAES_TB_TYPE4 tp4;
//    cout << m1 << "\n\n" << m2 << "\n\n" << m3 << "\n";
//    
//    makeXorTable(tp4, m1, m2, m3);
//    
//    for (int i=0; i<256; i++) {
//        printByte(tp4[i]); cout << ",";
//        if (i % 8 == 7) {
//            cout << "\n";
//        }
//    }
    
    
//    NTL::mat_GF2 m1, m2 ,m3, m4;
//    m1 = randomMixingBijection(m1, 4);
//    m2 = randomMixingBijection(m2, 4);
//    NTL::inv(m3, m1);  NTL::inv(m4, m2);
//    cout << m1 << "\n\n" << m2 << endl;
//    printByte( byteMul2Mat(0xff, m1, m2)  );
//    cout << m3 << "\n\n" << m4;
    
    
//    srand((unsigned)time(NULL));
//    NTL::mat_GF2 bij,inv,mul;
//    for(int i=0;i<1;i++){
//        cout << randomMixingBijection(bij, 128) << endl;
//        NTL::GF2 det = NTL::determinant(bij);
//        cout << det << endl;
//        if (det != 1) {
//            cout << "single" << endl;
//        }
//    }
    //sleep(3000);
    return 0;
}
