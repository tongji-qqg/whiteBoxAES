//
//  waesGenerator.h
//  whiteboxAes
//
//  Created by bryce on 15/5/25.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#ifndef __whiteboxAes__waesGenerator__
#define __whiteboxAes__waesGenerator__

#include <stdio.h>
#include <time.h>
#include <iostream>
#include <unistd.h>
#include <NTL/mat_GF2.h>
#include <NTL/vec_GF2.h>
#include "bijection.h"
#include "type.h"

//
//  Mixing bijection (linear transformation represented as GF(2) matrix)
//
typedef struct _MB_TABLE {
    //int         type;
    NTL::mat_GF2     mb;
    NTL::mat_GF2     inv;
    
    _MB_TABLE(void) {
        
    }
} MB_TABLE;

typedef MB_TABLE MB08x08_TABLE;
typedef MB_TABLE MB32x32_TABLE;
typedef MB_TABLE MB128x128_TABLE;

template<keyLength L>
class BijectionTables{
public:
    MB128x128_TABLE iot[2];
    MB08x08_TABLE lt[L / 32 + 6][16];
    MB32x32_TABLE rt[L / 32 + 6][4];
};


using namespace std;
template<keyLength L>
class WaesGenerator{
    
private:
    static const TB256 sbox;
    static const TB256 invSbox;
    
    //Nb Number of columns (32-bit words) comprising the State. For this standard, Nb = 4.
    static const int m_Nb;
    
    //Nk Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4, 6, or 8.
    int m_Nk;
    
    //Nr Number of rounds, which is a function of Nk and Nb (which isfixed). For this standard, Nr = 10, 12, or 14.
    int m_Nr;
    
    static const int map[16];
    static const int mapinv[16];
    static const BYTE mc[4][4];
    
    BYTE m_key[L/8+1];
    BYTE m_w[4*4*(L/32+7)];
    
    TB256 tbox[L/32+6][16];
    W32b tybox[4][256];
    
    bool useIOident;  //
    bool use08ident;
    bool use32ident;
private:
    BYTE* rotWord(BYTE* word){
        BYTE tmp = word[0];
        for(int i=0;i<3;i++){
            word[i] = word[i+1];
        }
        word[3] = tmp;
        return word;
    }
    
    BYTE* subWord(BYTE* word){
        for(int i=0;i<4;i++){
            word[i] = sbox[word[i]];
        }
        return word;
    }
    
    BYTE* coefAdd(BYTE* word,int index){
        // only first 20 is useful
        static BYTE xtime[64] = {
            0x02,0x01,0x02,0x04,0x08,0x10,0x20,0x40,
            0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A,
            0x2F,0x5E,0xBC,0x63,0xC6,0x97,0x35,0x6A,
            0xD4,0xB3,0x7D,0xFA,0xEF,0xC5,0x91,0x39,
            0x72,0xE4,0xD3,0xBD,0x61,0xC2,0x9F,0x25,
            0x4A,0x94,0x33,0x66,0xCC,0x83,0x1D,0x3A,
            0x74,0xE8,0xCB,0x8D,0x01,0x02,0x04,0x08,
            0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8
        };
        word[0] ^= xtime[index];
        return word;
    }
    
    void expandKey(const BYTE *key);
    
    void generateRandomBijectionTables(BijectionTables<L> &bij);
    
    void generateTMCtables(const BYTE* key);
    
    void generateTableType1(WaesTables<L> &wtable, BijectionTables<L> &bij);
    
    void generateTableType2(WaesTables<L> &wtable, BijectionTables<L> &bij);
    
    void generateTableType3(WaesTables<L> &wtable, BijectionTables<L> &bij);
    
    void generateTableType4(WaesTables<L> &wtable, BijectionTables<L> &bij);
    
public:
    WaesGenerator();
    
    ~WaesGenerator(){};
    
    int  generateKeyTables(const BYTE* key, WaesTables<L> &tables);
};

template<keyLength L>
const int WaesGenerator<L>::m_Nb = 4;

/*
 * S-box transformation table
 */
template<keyLength L>
const TB256 WaesGenerator<L>::sbox = {
    // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};// f

/*
 * Inverse S-box transformation table
 */
template<keyLength L>
const TB256 WaesGenerator<L>::invSbox = {
    // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // a
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // b
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // c
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // d
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // e
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};// f

template<keyLength L>
const int WaesGenerator<L>::map[16] = {
    0, 5, 10,15,
    4, 9, 14,3,
    8, 13,2, 7,
    12,1, 6, 11
};
template<keyLength L>
const int WaesGenerator<L>::mapinv[16] = {
    0, 13, 10,  7,
    4,  1, 14, 11,
    8,  5,  2, 15,
    12, 9,  6,  3
};
template<keyLength L>
const BYTE WaesGenerator<L>::mc[4][4] = {
    {0x02, 0x01, 0x01, 0x03},
    {0x03, 0x02, 0x01, 0x01},
    {0x01, 0x03, 0x02, 0x01},
    {0x01, 0x01, 0x03, 0x02}};

template<keyLength L>
void WaesGenerator<L>::expandKey(const BYTE *key){
    
    BYTE temp[4];
    for(int i=0;i < L/8;i++){
        m_w[i] = key[i];
    }
    
    for(int i=m_Nk;i < m_Nb * (m_Nr + 1);i++){
        temp[0] = m_w[4 * (i - 1) + 0];
        temp[1] = m_w[4 * (i - 1) + 1];
        temp[2] = m_w[4 * (i - 1) + 2];
        temp[3] = m_w[4 * (i - 1) + 3];
        
        if(i%m_Nk == 0){
            rotWord(temp);
            subWord(temp);
            coefAdd(temp,i/m_Nk);
        }else if(m_Nk>6 && i%m_Nk == 4){
            subWord(temp);
        }
        m_w[4*i+0] = m_w[4 * (i - m_Nk) + 0] ^ temp[0];
        m_w[4*i+1] = m_w[4 * (i - m_Nk) + 1] ^ temp[1];
        m_w[4*i+2] = m_w[4 * (i - m_Nk) + 2] ^ temp[2];
        m_w[4*i+3] = m_w[4 * (i - m_Nk) + 3] ^ temp[3];
        
    }
}

// random generate mixingbijection
// uses by total white box encrypt process
template<keyLength L>
void WaesGenerator<L>::generateRandomBijectionTables(BijectionTables<L>&bij){
    if (this->useIOident) {
        NTL::ident(bij.iot[0].mb, 128);
        NTL::ident(bij.iot[1].mb, 128);
    }
    else{
        randomMixingBijection(bij.iot[0].mb, 128);
        randomMixingBijection(bij.iot[1].mb, 128);
    }
    NTL::inv(bij.iot[0].inv, bij.iot[0].mb);
    NTL::inv(bij.iot[1].inv, bij.iot[1].mb);
    
    for (int i=0; i<m_Nr; i++) {
        for (int j=0; j<16; j++) {
            
            //if (this->use08ident || i >= 9){
            if (this->use08ident){
                NTL::ident(bij.lt[i][j].mb, 8);
            }else{
                randomMixingBijection(bij.lt[i][j].mb,8);
            }
            NTL::inv(bij.lt[i][j].inv, bij.lt[i][j].mb);
        }
    }
    
    for (int i=0; i<m_Nr; i++) {
        for (int j=0; j<4; j++) {
            
            if (this->use32ident) {
                NTL::ident(bij.rt[i][j].mb, 32);
            }else{
                randomMixingBijection(bij.rt[i][j].mb, 32);
            }
            NTL::inv(bij.rt[i][j].inv, bij.rt[i][j].mb);
        }
    }
    
}




template<keyLength L>
void  WaesGenerator<L>::generateTMCtables(const BYTE* key){
    
    expandKey(key);
    
    // Tbox
    int i = 0;
    
    for (i=0; i<m_Nr-1; i++) {
        for(int j=0;j<16;j++){
            for (int k=0; k<=255; k++) {
                tbox[i][j][k] = sbox[(BYTE)k ^ m_w[i*16+map[j]]];
            }
        }
    }
    for(int j=0;j<16;j++){
        for (int k=0; k<256; k++) {
            tbox[i][j][k] = sbox[(BYTE)k ^ m_w[ i*16+map[j]]] ^ m_w[m_Nr*16 + j];
            //tables.tbox10[j][k] = tbox[i][j][k];
        }
    }
    
    // Tybox
    for (int j=0; j<256; j++) {
        BYTE t = (BYTE)j;
        
        for (int k=0; k<4; k++) {
            tybox[k][j].B[0] = gmult(t, mc[k][0]);
            tybox[k][j].B[1] = gmult(t, mc[k][1]);
            tybox[k][j].B[2] = gmult(t, mc[k][2]);
            tybox[k][j].B[3] = gmult(t, mc[k][3]);
        }
    }

}

template<keyLength L>
void WaesGenerator<L>::generateTableType1(WaesTables<L> &wtable, BijectionTables<L> &bij){
    // 1a
    W128b temp;
    NTL::mat_GF2 inpartition[16],outpartition[16];
    for (int i=0; i<16; i++) {
        inpartition[i].SetDims(128, 8);
        outpartition[i].SetDims(128, 8);
        for (int j=0; j<128; j++) {
            for (int k=0; k<8; k++) {
                inpartition[i][j][k] = bij.iot[0].inv[j][i*8+k];
                outpartition[i][j][k] = bij.iot[0].inv[j][i*8+k];
            }
        }
    }
    for (int i=0; i<256; i++) {
        for (int j=0; j<16; j++) {
            // input decoding
            NTL::vec_GF2 vec,res;
            Byte2Vec((BYTE)i, vec, 0);
            NTL::mul(res, inpartition[j], vec);
            Vec2Byte( res, temp.B, 128);
            
            //W128CP(temp,wtable.et1[0][j][i]);
            // l 0
            for (int k=0; k<16; k++) {
                NTL::vec_GF2 sec;
                Byte2Vec(temp.B[k], sec, 0, 8);
                NTL::mul(res, bij.lt[0][mapinv[k]].mb, sec);
                Vec2Byte(res, &wtable.et1[0][j][i].B[k], 8);
            }
        }
    }
    
    // 1b
    NTL::vec_GF2 vec8, res8;
    BYTE byte;
    for (int i=0; i<16; i++) {
        for (int j=0; j<256; j++) {
            // l ^ -1
            Byte2Vec((BYTE)j, vec8, 0);
            NTL::mul(res8, bij.lt[m_Nr-1][i].inv, vec8);
            Vec2Byte(res8, &byte, 8);
            
            // tbox
            byte = tbox[m_Nr -1][i][byte];
            
            //wtable.tbox10[i][j] = byte;
            // out encoding
            NTL::vec_GF2 vec,res;
            Byte2Vec(byte, vec, 0);
            NTL::mul(res, outpartition[i], vec);
            Vec2Byte(res, temp.B, 128);
            W128CP(temp, wtable.et1[1][i][j]);
        }

    }
}

template<keyLength L>
void WaesGenerator<L>::generateTableType2(WaesTables<L> &wtable, BijectionTables<L> &bij){
    // l^-1
    NTL::vec_GF2 vec8,res8,vec32,res32;
    BYTE byte;
    W32b temp;
    vec8.SetLength(8);vec32.SetLength(32);
    //
    for (int i=0; i<m_Nr-1; i++) {
        for (int j=0; j<16; j++) {
            for (int k=0; k<256; k++) {
                
                // l^-1
                Byte2Vec((BYTE)k, vec8, 0);
                NTL::mul(res8, bij.lt[i][j].inv,vec8);
                Vec2Byte(res8, &byte, 8);
                
                // TMC
                temp.l = tybox[j%4][tbox[i][j][byte]].l;
                
                // R
                W32b2Vec(temp, vec32);
                NTL::mul(res32, bij.rt[i][j/4].mb, vec32);
                Vec2W32b(res32,temp);
                wtable.et2[i][j][k].l = temp.l;
            }
        }
    }
}

template<keyLength L>
void WaesGenerator<L>::generateTableType3(WaesTables<L> &wtable, BijectionTables<L> &bij){
    W32b temp1,temp2;
    NTL::vec_GF2 vec8,res8;
    for (int i=0; i<m_Nr - 1; i++) {
        for (int j=0; j<16; j++) {
            for (int k=0;k<256; k++) {
                // R ^ -1
                NTL::vec_GF2 vec32,res32;
                Byte2Vec((BYTE)k, vec32, (j%4)*8,32);
                NTL::mul(res32, bij.rt[i][j/4].inv, vec32);
                Vec2W32b(res32, temp1);
                
                // L
                for (int m=0; m<4; m++) {
                    Byte2Vec(temp1.B[m], vec8, 0);
                    NTL::mul(res8, bij.lt[i+1][mapinv[(j/4)*4 + m]].mb, vec8);
                    Vec2Byte(res8, &temp2.B[m], 8);
                }
                wtable.et3[i][j][k].l = temp2.l;
            }
        }
    }
}

template<keyLength L>
void WaesGenerator<L>::generateTableType4(WaesTables<L> &wtable, BijectionTables<L> &bij){
    
}



template<keyLength L>
int  WaesGenerator<L>::generateKeyTables(const BYTE * key, WaesTables<L> &tables){
    
    BijectionTables<L> bijtable;
    
    generateTMCtables(key);
    
    generateRandomBijectionTables(bijtable);
    
    generateTableType1(tables, bijtable);
    
    generateTableType2(tables, bijtable);
    
    generateTableType3(tables, bijtable);
    
    generateTableType4(tables, bijtable);
    
    // just for test
    for(int j=0;j<16;j++){
        for (int k=0; k<256; k++) {
            tables.tbox10[j][k] = tbox[m_Nr - 1][j][k];
        }
    }
    
    return 0;
}




template<keyLength L>
WaesGenerator<L>::WaesGenerator():m_Nk(L/32),m_Nr(L/32+6){
    this->useIOident = true;
    this->use08ident = false;
    this->use32ident = false;
}
#endif /* defined(__whiteboxAes__waesGenerator__) */
