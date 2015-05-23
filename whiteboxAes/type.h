//
//  type.h
//  whiteboxAes
//
//  Created by bryce on 15/5/23.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#ifndef whiteboxAes_type_h
#define whiteboxAes_type_h

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

enum keyLength{key128=128,key192=192,key256=256};

#endif
