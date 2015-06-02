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
#include <NTL/mat_GF2.h>
#include <NTL/GF2.h>

# define SAFE_DELETE(p) if(NULL != p){delete p; p = NULL;}

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

inline bool compareBlock(const BYTE* b1, const BYTE* b2, int length = 16){
    bool flag = true;
    for(int j=0;j<length;j++){
        printByte(b1[j]);
        std::cout << ",";
        printByte(b2[j]);
        std::cout << std::endl;
        if (b1[j] != b2[j]) {
            flag = false;
        }
    }
    return flag;
}

//inline void Byte2Vec(BYTE b, NTL::vec_GF2 &vec, int offset,int size=8){
//    vec.SetLength(size);
//    
//    for (int i=7; i>=0; i--) {
//        vec[i + offset] = b & 0x01;
//        b = b >> 1;
//    }
//}
//
//inline void W32b2Vec(W32b& w,NTL::vec_GF2 &vec){
//    for (int i=0; i<4; i++) {
//        Byte2Vec(w.B[i], vec, i*8,32);
//    }
//}
//
//inline void Vec2Byte(NTL::vec_GF2 &vec, BYTE* b,int size){
//
//    for (int i=0; i<(size/8); i++) {
//        b[i] = (BYTE)NTL::rep(vec.get(i * 8));
//        for (int j=1; j<8; j++) {
//            b[i] = b[i] << 1;
//            b[i] ^= (BYTE)NTL::rep(vec.get(i*8 + j));
//        }
//    }
//}
//
//inline void Vec2W32b(NTL::vec_GF2 &vec, W32b& w){
//    Vec2Byte(vec, w.B, 32);
//}

// numOfBits is input byte bits number
inline void matMulByte(BYTE *res, NTL::mat_GF2 & mat, const BYTE * b, int numOfBits=8, bool isInv = false){
    NTL::vec_GF2 mv, rv;
    mv.SetLength(numOfBits);
    int numOfBytes = numOfBits / 8;
    for (int i=0; i < numOfBytes ; i++) {
        BYTE t = b[i];
        for (int j=7; j>=0; j--) {
            mv[j + i*8] = t & 0x01;
            t = t >> 1;
        }
    }
    if (isInv) {
        NTL::mul(rv,mv,mat);
    }else{
        NTL::mul(rv, mat, mv);
    }
    int outOfBytes = (int)rv.length() / 8;
    for (int i = 0 ; i < outOfBytes; i++) {
        res[i] = (BYTE)NTL::rep(rv.get(i * 8));
        for (int j=1; j<8; j++) {
            res[i] = res[i] << 1;
            res[i] ^= (BYTE)NTL::rep(rv.get(i*8 + j));
        }
    }
}

inline BYTE byteMul2Mat(BYTE b, NTL::mat_GF2 &mh, NTL::mat_GF2 &ml){
    NTL::vec_GF2 vh, vl, rh, rl;
    vh.SetLength(4);vl.SetLength(4);
    BYTE t = b;
    for (int i = 3; i >= 0; i--) {
        vl[i] = t & 0x01; t = t >> 1;
    }
    for (int i = 3; i >= 0 ; i--) {
        vh[i] = t & 0x01; t = t >> 1;
    }
    NTL::mul(rl, ml, vl);
    NTL::mul(rh, mh, vh);
    t = 0;
    for (int i = 0; i < 4; i++ ) {
        t ^= (BYTE)NTL::rep(rh.get(i)); t = t << 1;
    }
    for (int i = 0; i < 3; i++ ) {
        t ^=  (BYTE)NTL::rep(rl.get(i)); t = t << 1;
    }
    t = t + (BYTE)NTL::rep(rl.get(3));
    return t;
}

inline void makeXorTable(WAES_TB_TYPE4 & table, NTL::mat_GF2& mh, NTL::mat_GF2 &ml, NTL::mat_GF2 &mo){
    NTL::vec_GF2 vec, res; vec.SetLength(4);
    for (int i = 0; i < TABLE_8BIT_IN_SIZE; i++) {
        BYTE r = byteMul2Mat((BYTE)i, mh, ml);
        BYTE high = r >> 4;
        BYTE low  = r &  0x0f;
        BYTE t    = high ^ low;
        for (int j = 3; j >= 0; j--) {
            vec[j] = t & 0x01; t = t >> 1;
        }
        NTL::mul(res, mo, vec);
        t = 0;
        for (int j = 0; j < 3; j++){
            t  ^= (BYTE)NTL::rep(res.get(j)); t = t << 1;
        }
        t ^= (BYTE)NTL::rep(res.get(3));
        table[i] = (BIT4)t;
    }
}


inline void W128bXor(W128b&x, W128b &a, W128b&b){
    for (int i=0; i<4; i++) {
        x.l[i] = a.l[i] ^ b.l[i];
    }
}

inline void W128bXor(W128b&x, W128b &a, W128b&b, WAES_TB_TYPE4(&t)[32]){
    BYTE byteHigh, byteLow, bit4High, bit4Low;
    for (int i=0; i<16; i++) {
        byteHigh = (a.B[i] & 0xf0) ^ (b.B[i] >> 4);
        byteLow  = (a.B[i] << 4 )  ^ (b.B[i] & 0x0f);
        bit4High = t[i * 2][byteHigh];
        bit4Low  = t[i * 2 + 1][byteLow];
        x.B[i] = (bit4High << 4) ^ (bit4Low & 0x0f);
    }
}


inline void W32bXor(W32b&x, W32b &a, W32b&b, WAES_TB_TYPE4(&t)[8]){
    BYTE byteHigh, byteLow, bit4High, bit4Low;
    for (int i=0; i<4; i++) {
        byteHigh = (a.B[i] & 0xf0) ^ (b.B[i] >> 4);
        byteLow  = (a.B[i] << 4 )  ^ (b.B[i] & 0x0f);
        bit4High = t[i * 2][byteHigh];
        bit4Low  = t[i * 2 + 1][byteLow];
        x.B[i] = (bit4High << 4) ^ (bit4Low & 0x0f);
    }
}



// shrink is make 256 byte table to 128 byte
// with first 4 bits removed
// this do reduce table size
// but i dont like it, 4bit is not friendly to program（cpu already 64!）reduce performance.
// just because mentor require me must do this,
// may be apply to some small memory device.
//
// |00|,|01|,|02|,|03|,|04|,|05|
//  |   /    /    /
//  |  /   /   /
//  | /  /  /
// |01|,|23|,|45|
//
inline BYTE lookShrankXorTable(WAES_TB_TYPE4S &t, BYTE index){
    
    BYTE comboByte = t[index / 2];
    if ( 0 == index % 2 ) {  // at high 4 bit
        comboByte = comboByte >> 4;
    }
    return comboByte;
}

inline void W128bShrankXor(W128b&x, W128b &a, W128b&b, WAES_TB_TYPE4S(&t)[32]){
    BYTE byteHigh, byteLow, bit4High, bit4Low;
    for (int i=0; i<16; i++) {
        byteHigh = (a.B[i] & 0xf0) ^ (b.B[i] >> 4);
        byteLow  = (a.B[i] << 4 )  ^ (b.B[i] & 0x0f);
        bit4High = lookShrankXorTable(t[i * 2], byteHigh);
        bit4Low  = lookShrankXorTable(t[i * 2 + 1], byteLow);
        x.B[i] = (bit4High << 4) ^ (bit4Low & 0x0f);
    }
}

inline void W32bShrankXor(W32b&x, W32b &a, W32b&b, WAES_TB_TYPE4S(&t)[8]){
    BYTE byteHigh, byteLow, bit4High, bit4Low;
    for (int i=0; i<4; i++) {
        byteHigh = (a.B[i] & 0xf0) ^ (b.B[i] >> 4);
        byteLow  = (a.B[i] << 4 )  ^ (b.B[i] & 0x0f);
        bit4High = lookShrankXorTable(t[i * 2], byteHigh);
        bit4Low  = lookShrankXorTable(t[i * 2 + 1], byteLow);
        x.B[i] = (bit4High << 4) ^ (bit4Low & 0x0f);
    }
}

// no use for make xor table, for this is sick
//BIT4 ht[16], lt[16]; // 4 bit is 16 total
//NTL::vec_GF2 vec, res; vec.SetLength(4);
//for (int i = 0; i < 16; i++) {
//    //
//    BIT4 temp = (BIT4)i;
//    for (int k = 3 ; k >= 0; k--) {
//        vec[k] = temp & 0x01; temp = temp >> 1;
//    }
//    
//    // high
//    NTL::mul(res, mh, vec);
//    temp = 0;
//    for (int k = 0; k < 3; k++) {
//        temp = temp + (BIT4)NTL::rep(res.get(k)); temp = temp << 1;
//    }
//    temp = temp + (BIT4)NTL::rep(res.get(3));
//    ht[i] = temp;
//    
//    // low
//    NTL::mul(res, ml, vec);
//    temp = 0;
//    for (int k = 0; k < 3; k++) {
//        temp = temp + (BIT4)NTL::rep(res.get(k)); temp = temp << 1;
//    }
//    temp = temp + (BIT4)NTL::rep(res.get(3));
//    lt[i] = temp;
//}
//for (int i = 0; i < 16; i++) {
//    for (int j = 0; j < 16; j++) {
//        
//    }
//}

#endif
