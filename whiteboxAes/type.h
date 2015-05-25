//
//  type.h
//  whiteboxAes
//
//  Created by bryce on 15/5/23.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#ifndef whiteboxAes_type_h
#define whiteboxAes_type_h

#define N_BYTES 16
//
// 自定义数据类型
//
typedef unsigned char BYTE;

typedef unsigned long DWORD;

typedef union _W32B{
    BYTE B[4];
    unsigned int l;
} W32b;

typedef union _W128B{
    BYTE B[16];
    unsigned int l[4];
} W128b;

typedef BYTE TB256[256];

// TYPE 1 tables
// DEF: G * INP
// Input is 1 byte, output is 128bit wide
typedef W128b WAES_TB_TYPE1[256];

// TYPE 2 tables (T, Ty, MB boxes)
// DEF: MB * Tyi * T * L2 ^{-1} (x)
// Input is 1 byte (2x BITS4), output is 32bit wide (after MC)
typedef W32b WAES_TB_TYPE2[256];

// TYPE 3 tables
// DEF: L * MB ^{-1} (x)
// Input is 1 byte (2x BITS4), output is 32bit wide
typedef W32b WAES_TB_TYPE3[256];


enum keyLength{key128=128,key192=192,key256=256};


template<keyLength L>
class WaesTables{
public:
    WAES_TB_TYPE1 et1[2][16];
    WAES_TB_TYPE2 et2[L/32 + 5][16];
    WAES_TB_TYPE3 et3[L/32 + 5][16];
    TB256 tbox10[16];
    
    WAES_TB_TYPE1 dt1[2][16];
    WAES_TB_TYPE2 dt2[L/32 + 5][16];
    WAES_TB_TYPE3 dt3[L/32 + 5][16];
};
#endif
