//
//  util.h
//  whiteboxAes
//
//  Created by bryce on 15/5/23.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#ifndef whiteboxAes_util_h
#define whiteboxAes_util_h

#include "type.h"

BYTE gmult(BYTE a, BYTE b);
void printByte(BYTE b);
void matShow(const BYTE *out,int size=16);
inline void W32CP(W32b &s, W32b& t){
    t.l = s.l;
}
inline void W128CP(W128b &s, W128b& t){
    t.l[0] = s.l[0];
    t.l[1] = s.l[1];
    t.l[2] = s.l[2];
    t.l[3] = s.l[3];
}
#endif
