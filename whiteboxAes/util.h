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
#include <NTL/vec_GF2.h>
#include <NTL/GF2.h>

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
inline void Byte2Vec(BYTE b, NTL::vec_GF2 &vec, int offset,int size=8){
    vec.SetLength(size);
    
    for (int i=7; i>=0; i--) {
        vec[i + offset] = b & 0x01;
        b = b >> 1;
    }
}

inline void W32b2Vec(W32b& w,NTL::vec_GF2 &vec){
    for (int i=0; i<4; i++) {
        Byte2Vec(w.B[i], vec, i*8,32);
    }
}

inline void Vec2Byte(NTL::vec_GF2 &vec, BYTE* b,int size){

    for (int i=0; i<(size/8); i++) {
        b[i] = (BYTE)NTL::rep(vec.get(i * 8));
        for (int j=1; j<8; j++) {
            b[i] = b[i] << 1;
            b[i] ^= (BYTE)NTL::rep(vec.get(i*8 + j));
        }
    }
}

inline void Vec2W32b(NTL::vec_GF2 &vec, W32b& w){
    Vec2Byte(vec, w.B, 32);
}

inline void W128bXor(W128b&x, W128b &a, W128b&b){
    for (int i=0; i<4; i++) {
        x.l[i] = a.l[i] ^ b.l[i];
    }
}
#endif
