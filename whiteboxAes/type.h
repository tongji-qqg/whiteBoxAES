//
//  type.h
//  whiteboxAes
//
//  Created by bryce on 15/5/23.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#ifndef whiteboxAes_type_h
#define whiteboxAes_type_h

#define BLOCK_BIT_NUM  128  // AES 一个block是128bit
#define BLOCK_BYTE_NUM  16  // AES 一个block是16Byte
#define SECTION_NUM      4  // AES 每一轮划分为4个section分别处理
#define SECTION_BYTE_NUM 4  // AES 每一个section里面有4个Byte
#define VALUES_IN_BYTE 256
#define TABLE_8BIT_IN_SIZE 256
#define TEMPLATE_ROUND_NUM (L / 32 + 6) // L是key bits
//
// 自定义数据类型
//
typedef unsigned char BYTE;

typedef union _W32B{
    BYTE B[4];
    unsigned int l;
} W32b;

typedef union _W128B{
    BYTE B[16];
    unsigned int l[4];
} W128b;

typedef BYTE TB256[TABLE_8BIT_IN_SIZE];

typedef BYTE BIT4;
// TYPE 1 tables
// DEF: G * INP
// Input is 1 byte, output is 128bit wide
typedef W128b WAES_TB_TYPE1[TABLE_8BIT_IN_SIZE];

// TYPE 2 tables (T, Ty, MB boxes)
// DEF: MB * Tyi * T * L2 ^{-1} (x)
// Input is 1 byte (2x BITS4), output is 32bit wide (after MC)
typedef W32b WAES_TB_TYPE2[TABLE_8BIT_IN_SIZE];

// TYPE 3 tables
// DEF: L * MB ^{-1} (x)
// Input is 1 byte (2x BITS4), output is 32bit wide
typedef W32b WAES_TB_TYPE3[TABLE_8BIT_IN_SIZE];


typedef BIT4 WAES_TB_TYPE4[TABLE_8BIT_IN_SIZE];


typedef BIT4 WAES_TB_TYPE4S[TABLE_8BIT_IN_SIZE / 2];


enum keyLength{key128=128,key192=192,key256=256};


template<keyLength L>
class WaesTables{
    
public:
    
    //      t4 fot t1a,t1b    | 15 128  xor | 128 = 32 x 4
    WAES_TB_TYPE4 ex0[2]       [8 + 4 + 2 + 1] [32];
    
    //             t1a,t1b    | 128 = 16 x 8
    WAES_TB_TYPE1 et1[2]       [16];
    
    //             rounds     | 128 = 16 x 8
    WAES_TB_TYPE2 et2[L/32 + 5][16];
    
    //             rounds     | 128 = 16 x 8
    WAES_TB_TYPE3 et3[L/32 + 5][16];
    
    //             rounds     | 12 section   | 32 = 8 x 4
    WAES_TB_TYPE4 ex4t2t3[L/32 + 5][12]       [8];
    WAES_TB_TYPE4 ex4t3t2[L/32 + 5][12]       [8];

};

template<keyLength L>
class WaesTablesShrankXor{
    
public:
    
    //      t4 fot t1a,t1b    | 15 128  xor | 128 = 32 x 4
    WAES_TB_TYPE4S ex0[2]       [8 + 4 + 2 + 1] [32];
    
    //             t1a,t1b    | 128 = 16 x 8
    WAES_TB_TYPE1  et1[2]       [16];
    
    //             rounds     | 128 = 16 x 8
    WAES_TB_TYPE2  et2[L/32 + 5][16];
    
    //             rounds     | 128 = 16 x 8
    WAES_TB_TYPE3  et3[L/32 + 5][16];
    
    //             rounds     | 12 section   | 32 = 8 x 4
    WAES_TB_TYPE4S ex4t2t3[L/32 + 5][12]       [8];
    WAES_TB_TYPE4S ex4t3t2[L/32 + 5][12]       [8];
    
};
#endif
