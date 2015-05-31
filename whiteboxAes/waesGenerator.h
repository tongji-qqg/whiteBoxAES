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
#include "bijection.h"
#include "type.h"

//
//  Mixing bijection (linear transformation represented as GF(2) matrix)
//
typedef struct _MB_TABLE {
    //int         type;
    NTL::mat_GF2     mb;
    NTL::mat_GF2     inv;
    
} MB_TABLE;


typedef MB_TABLE MB04x04_TABLE;
typedef MB_TABLE MB08x08_TABLE;
typedef MB_TABLE MB32x32_TABLE;
typedef MB_TABLE MB128x128_TABLE;


template<keyLength L>
class BijectionTables{
public:
    
    // type [1a, 1b] xor
    MB04x04_TABLE x0[2][16 + 8 + 4 + 2 + 1][32];
    
    // type t2 t3 xor
    MB04x04_TABLE x1[L / 32 + 6 - 1][(4 + 2 + 1)*4][8];
    
    // type t3 t2 xor
    MB04x04_TABLE x2[L / 32 + 6 - 1][(4 + 2 + 1)*4][8];
    
    MB08x08_TABLE lt[L / 32 + 6][16];
    
    MB32x32_TABLE rt[L / 32 + 6][4];
    
    MB128x128_TABLE iot[2];
};





using namespace std;
template<keyLength L>
class WaesGenerator{
    
private:
    static const TB256 sbox;
    static const TB256 sboxInv;
    
    //Nb Number of columns (32-bit words) comprising the State. For this standard = 4.
    static const int m_nSection;
    
    //Nk Number of 32-bit words comprising the Cipher Key. For this standard = 4, 6, or 8.
    int m_nKeyIn32;
    
    //Nr Number of rounds, which is a function of Nk and Nb (which isfixed). For this standard = 10, 12, or 14.
    int m_nRounds;
    
    static const int  emptyMap          [BLOCK_BYTE_NUM];
    static const int  shiftRow          [BLOCK_BYTE_NUM];
    static const int  shiftRowInv       [BLOCK_BYTE_NUM];
    static const int  xorShiftRow1      [BLOCK_BYTE_NUM]; // make xor table t3 -> t2, choose section
    static const int  xorShiftRow2      [BLOCK_BYTE_NUM]; // make xor table t3 -> t2, choose index in section
    static const int  xorShiftRow1Decode[BLOCK_BYTE_NUM]; // xor decode table t3 -> t2, choose section
    static const int  xorShiftRow2Decode[BLOCK_BYTE_NUM]; // xor decode table t3 -> t2, choose index in section
    static const BYTE mc   [SECTION_NUM][SECTION_BYTE_NUM];
    static const BYTE mcInv[SECTION_NUM][SECTION_BYTE_NUM];
    
    BYTE m_roundKey[4*4*(L/32+7)];
    
    TB256 tbox[L/32+6][BLOCK_BYTE_NUM];
    W32b tybox[4][256];
    
    NTL::mat_GF2 exf, exg;
    
    bool useIOident;  //
    bool use04ident;
    bool use08ident;
    bool use32ident;
    
    bool haveSetExEncoding;
    
    bool use04table;
private:
    
    /*
     * --------------------------------------
     *       for generate round key
     * --------------------------------------
     */
    BYTE* rotWord(BYTE* word){
        BYTE tmp = word[0];
        
        for(int i = 0; i < SECTION_BYTE_NUM - 1 ; i++){
            word[i] = word[i+1];
        }
        word[3] = tmp;
        
        return word;
    }
    
    BYTE* subWord(BYTE* word){
        for(int i = 0;i < SECTION_BYTE_NUM; i++){
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
    
    /* 
     * --------------------------------------
     *       for generate lookup table
     * --------------------------------------
     */
    void generateRandomBijectionTables(BijectionTables<L> &bij, bool isEncrypt = true);
    
    void generateTMCtables(const BYTE* key, bool isEncrypt = true);
    
    void generateTableType1(WaesTables<L> &wtable, BijectionTables<L> &bij, bool isEncrypt = true);
    
    void generateTableType2(WaesTables<L> &wtable, BijectionTables<L> &bij, bool isEncrypt = true);
    
    void generateTableType3(WaesTables<L> &wtable, BijectionTables<L> &bij, bool isEncrypt = true);
    
    void generateTableType4(WaesTables<L> &wtable, BijectionTables<L> &bij, bool isEncrypt = true);
    
public:
    WaesGenerator();
    
    ~WaesGenerator(){};
    
    int setExternalEncoding(NTL::mat_GF2 &f, NTL::mat_GF2 &g);
    
    int  generateKeyTables(const BYTE* key, WaesTables<L> &tables, bool isEncrypt = true);
};


template<keyLength L>
int WaesGenerator<L>::setExternalEncoding(NTL::mat_GF2 &f, NTL::mat_GF2 &g){
    if (f.NumCols() == 128 && f.NumRows() == 128 &&
        g.NumCols() == 128 && g.NumRows() == 128) {
        this->exf  = f;
        this->exg  = g;
        this->haveSetExEncoding = true;
        return 0;
    }
    return 1;
}


template<keyLength L>
void WaesGenerator<L>::expandKey(const BYTE *key){
    
    BYTE temp[SECTION_BYTE_NUM];
    for(int i = 0;i < L / 8 ; i++){
        m_roundKey[i] = key[i];
    }
    
    for(int i=m_nKeyIn32;i < m_nSection * (m_nRounds + 1);i++){
        temp[0] = m_roundKey[4 * (i - 1) + 0];
        temp[1] = m_roundKey[4 * (i - 1) + 1];
        temp[2] = m_roundKey[4 * (i - 1) + 2];
        temp[3] = m_roundKey[4 * (i - 1) + 3];
        
        if( i % m_nKeyIn32 == 0){
            
            coefAdd(subWord(rotWord(temp)), i / m_nKeyIn32);
            
        }else if( m_nKeyIn32 > 6 && i % m_nKeyIn32 == 4){
            
            subWord(temp);
        
        }
        m_roundKey[4*i+0] = m_roundKey[4 * (i - m_nKeyIn32) + 0] ^ temp[0];
        m_roundKey[4*i+1] = m_roundKey[4 * (i - m_nKeyIn32) + 1] ^ temp[1];
        m_roundKey[4*i+2] = m_roundKey[4 * (i - m_nKeyIn32) + 2] ^ temp[2];
        m_roundKey[4*i+3] = m_roundKey[4 * (i - m_nKeyIn32) + 3] ^ temp[3];
        
    }
}

// random generate mixingbijection
// uses by total white box encrypt process
template<keyLength L>
void WaesGenerator<L>::generateRandomBijectionTables(BijectionTables<L>&bij,bool isEncrypt){
    if (this->useIOident) {
        NTL::ident(bij.iot[0].mb, 128);
        NTL::ident(bij.iot[1].mb, 128);
    }else if (this->haveSetExEncoding){
        //  G.  Enc().F
        //  F-1.Dec().G-1
        bij.iot[0].mb = exf;
        bij.iot[1].mb = exg;
    }else{
        randomMixingBijection(bij.iot[0].mb, 128);
        randomMixingBijection(bij.iot[1].mb, 128);
    }
    NTL::inv(bij.iot[0].inv, bij.iot[0].mb);
    NTL::inv(bij.iot[1].inv, bij.iot[1].mb);
    
    for (int i = 0; i<m_nRounds; i++) {
        for (int j = 0; j < BLOCK_BYTE_NUM ; j++) {
            
            //if (this->use08ident && i < 9){
            if ( this->use08ident ){
                NTL::ident(bij.lt[i][j].mb, 8);
            }else{
                randomMixingBijection(bij.lt[i][j].mb,8);
            }
            NTL::inv(bij.lt[i][j].inv, bij.lt[i][j].mb);
        }
    }
    
    for (int i=0; i<m_nRounds; i++) {
        for (int j = 0; j < SECTION_NUM ; j++) {
            
            if (this->use32ident) {
                NTL::ident(bij.rt[i][j].mb, 32);
            }else{
                randomMixingBijection(bij.rt[i][j].mb, 32);
            }
            NTL::inv(bij.rt[i][j].inv, bij.rt[i][j].mb);
        }
    }
    
    for (int i=0; i< m_nRounds - 1; i++) {
        for (int j=0; j<28; j++) {
            for (int k=0; k<8; k++) {
                
                //if (this->use04ident && i == 0 && (j % 7) == 6) {
                if (this->use04ident){
                    NTL::ident(bij.x1[i][j][k].mb, 4);
                }else{
                    randomMixingBijection(bij.x1[i][j][k].mb, 4);
                }
                NTL::inv(bij.x1[i][j][k].inv, bij.x1[i][j][k].mb);
            }
        }
    }
    
    for (int i=0; i< m_nRounds - 1; i++) {
        for (int j=0; j<28; j++) {
            for (int k=0; k<8; k++) {
                
                if (this->use04ident) {
                    NTL::ident(bij.x2[i][j][k].mb, 4);
                }else{
                    randomMixingBijection(bij.x2[i][j][k].mb, 4);
                }
                NTL::inv(bij.x2[i][j][k].inv, bij.x2[i][j][k].mb);
            }
        }
    }
    
    
    for (int i=0; i<2; i++) {
        for (int j=0; j< 16 + 8 + 4 + 2 + 1; j++) {
            for (int k = 0 ; k < 32; k++) {
                //if (this->use04ident || j == 30) {
                if (this->use04ident || (i == 1 && j == 30)) { // last is empty
                    NTL::ident(bij.x0[i][j][k].mb, 4);
                }else{
                    randomMixingBijection(bij.x0[i][j][k].mb, 4);
                }
                NTL::inv(bij.x0[i][j][k].inv, bij.x0[i][j][k].mb);
            }
            
        }
    }
}




template<keyLength L>
void  WaesGenerator<L>::generateTMCtables(const BYTE* key, bool isEncrypt){
    
    expandKey(key);
    
    const BYTE (&mcOp)[SECTION_NUM][SECTION_BYTE_NUM] = isEncrypt ? mc       : mcInv;
    
    // Tbox
    int i = 0;
    
    if (isEncrypt) {
        for (i = 0; i < m_nRounds - 1; i++) {
            for(int j = 0 ; j < BLOCK_BYTE_NUM ;j++){
                for (int k = 0; k < TABLE_8BIT_IN_SIZE ; k++) {
                    tbox[i][j][k] = sbox[ (BYTE)k ^ m_roundKey[ i * BLOCK_BYTE_NUM + shiftRow[j]] ];
                }
            }
        }
        
        for(int j = 0; j < BLOCK_BYTE_NUM ; j++){
            for (int k = 0; k < TABLE_8BIT_IN_SIZE ; k++) {
                tbox[i][j][k] = sbox[(BYTE)k ^ m_roundKey[ i * BLOCK_BYTE_NUM + shiftRow[j] ]] ^
                m_roundKey[ m_nRounds * BLOCK_BYTE_NUM + j];
            }
        }
    }else{
        
        for (i = 0; i < m_nRounds ; i++) {
            for(int j = 0 ; j < BLOCK_BYTE_NUM ;j++){
                for (int k = 0; k < TABLE_8BIT_IN_SIZE ; k++) {
                    
                    tbox[i][j][k] = sboxInv[k]  ^ m_roundKey[i * BLOCK_BYTE_NUM + j];
                }
            }
        }
    }
    
    
    // Tybox
    for (int j = 0; j < TABLE_8BIT_IN_SIZE ; j++) {
        BYTE t = (BYTE)j;
        
        for (int k = 0; k < SECTION_NUM ; k++) {
            tybox[k][j].B[0] = gmult(t, mcOp[k][0]);
            tybox[k][j].B[1] = gmult(t, mcOp[k][1]);
            tybox[k][j].B[2] = gmult(t, mcOp[k][2]);
            tybox[k][j].B[3] = gmult(t, mcOp[k][3]);
        }
    }

}





template<keyLength L>
void WaesGenerator<L>::generateTableType1(WaesTables<L> &wtable, BijectionTables<L> &bij, bool isEncrypt){
    
    // partition: 128 x 128 -> 128 x 8 + 128 x 8 + 128 x 8 + 128 x 8
    W128b temp;
    const int  (&shiftRowOp) [BLOCK_BYTE_NUM] = isEncrypt ? shiftRowInv  : shiftRow;
    const int  (&xorShiftOp1)[BLOCK_BYTE_NUM] = isEncrypt ? xorShiftRow1 : xorShiftRow1Decode;
    const int  (&xorShiftOp2)[BLOCK_BYTE_NUM] = isEncrypt ? xorShiftRow2 : xorShiftRow2Decode;
    
    NTL::mat_GF2 inpartition[16],outpartition[16];
    for (int i = 0; i < 16; i++) {
        inpartition[i].SetDims(128, 8);
        outpartition[i].SetDims(128, 8);
        for (int j=0; j<128; j++) {
            for (int k=0; k<8; k++) {
                inpartition[i][j][k] = bij.iot[0].inv[j][i*8+k];
                outpartition[i][j][k] = bij.iot[1].mb[j][i*8+k];
            }
        }
    }
    
    BYTE *lastRoundKey = m_roundKey + m_nRounds * 16;
    // 1a
    for (int i = 0; i < TABLE_8BIT_IN_SIZE; i++) {
        for (int j = 0; j < BLOCK_BYTE_NUM; j++) {
            // input decoding
            BYTE input = (BYTE)i;
            
            
            //        128 x 1 = 128 x 8   mul   8 x 1
            matMulByte(temp.B, inpartition[j], &input, 8);
        
            
            if (j == 0 && ! isEncrypt ){
                for (int k=0; k<16; k++) {
                    temp.B[k] ^= lastRoundKey[k];
                }
            }
            
            
            // l 0
            for (int k=0; k < BLOCK_BYTE_NUM; k++) {
                
                //          8 x 1                   =   8  x  8                 mul  8 x 1
                matMulByte(&wtable.et1[0][j][i].B[k], bij.lt[0][shiftRowOp[k]].mb, &temp.B[k], 8);
            }
        }
    }
    
    // 1b
    BYTE byte;
    for (int i = 0; i < BLOCK_BYTE_NUM; i++) {
        for (int j = 0; j < TABLE_8BIT_IN_SIZE ; j++) {
            // l ^ -1
            BYTE input = (BYTE)j;
            
            if ( this->use04table) {
                input = byteMul2Mat(input,
                                    bij.x2[ L / 32 + 4][ xorShiftOp1[i] ][ xorShiftOp2[i] ].inv,
                                    bij.x2[ L / 32 + 4][ xorShiftOp1[i] ][ xorShiftOp2[i] + 1].inv);
            }
            
            //         8 x 1 =  8  x  8                mul 8 x 1
            matMulByte(&byte, bij.lt[m_nRounds-1][i].inv, &input, 8);
            
            // tbox
            if ( isEncrypt ) {
                byte = tbox[m_nRounds -1][i][byte];
            }else{
                byte = tbox[0][i][byte];
            }
            
            
            // out encoding
            //         128  x  1            = 128 x 8      mul  8 x 1
            matMulByte(wtable.et1[1][i][j].B, outpartition[i], &byte, 8);
        }

    }
}

template<keyLength L>
void WaesGenerator<L>::generateTableType2(WaesTables<L> &wtable, BijectionTables<L> &bij, bool isEncrypt){
    // l^-1
    BYTE byte;
    W32b temp;
    
    const int  (&shiftRowOp) [BLOCK_BYTE_NUM] = isEncrypt ? shiftRow     : shiftRowInv;
    const int  (&xorShiftOp1)[BLOCK_BYTE_NUM] = isEncrypt ? xorShiftRow1 : xorShiftRow1Decode;
    const int  (&xorShiftOp2)[BLOCK_BYTE_NUM] = isEncrypt ? xorShiftRow2 : xorShiftRow2Decode;

    //
    for (int i = 0; i < m_nRounds - 1; i++) {
        for (int j = 0; j < BLOCK_BYTE_NUM; j++) {
            for (int k = 0; k < TABLE_8BIT_IN_SIZE; k++) {
                
                // l^-1
                
                BYTE input = (BYTE)k;
                if ( 0 == i && this->use04table) {
                    input = byteMul2Mat(input,
                                        bij.x0[0][30][shiftRowOp[ j ] * 2].inv,
                                        bij.x0[0][30][shiftRowOp[ j ] * 2 + 1].inv);
                }
                if ( 0 < i && this->use04table) {
                    input = byteMul2Mat(input,
                                        bij.x2[i - 1][ xorShiftOp1[j] ][ xorShiftOp2[j] ].inv,
                                        bij.x2[i - 1][ xorShiftOp1[j] ][ xorShiftOp2[j] + 1].inv);
                }
                
                
                //        8 x 1 = 8 x 8        mul  8 x 1
                matMulByte(&byte, bij.lt[i][j].inv, &input, 8);
                
                // TMC
                if ( isEncrypt ) {
                    temp.l = tybox[j%4][tbox[i][j][byte]].l;
                }else{
                    temp.l = tybox[j%4][tbox[m_nRounds - 1 - i][j][byte]].l;
                }
                
                
                // R
                //         32 x 1
                matMulByte(wtable.et2[i][j][k].B,
                           //= 32  x  32      mul 32 x 1
                           bij.rt[i][j/4].mb, temp.B, 32);
            }
        }
       
    }
}


template<keyLength L>
void WaesGenerator<L>::generateTableType3(WaesTables<L> &wtable, BijectionTables<L> &bij, bool isEncrypt){
    W32b temp1,temp2;
    const int (&shiftRowOp) [BLOCK_BYTE_NUM] = isEncrypt ? shiftRowInv     : shiftRow;
    
    // parition: 32 x 32  -> 32 x 8 + 32 x 8 + 32 x 8 + 32 x 8
    NTL::mat_GF2 partition[TEMPLATE_ROUND_NUM - 1][16];
    for (int r=0; r < TEMPLATE_ROUND_NUM - 1; r++) {
        for (int i = 0; i < BLOCK_BYTE_NUM ; i++) {
            
            partition[r][i].SetDims(32, 8);
            for (int j = 0 ; j < 32; j++) {
                for (int k = 0; k < 8; k++) {
                    partition[r][i][j][k] = bij.rt[r][i / 4].inv[j][(i % 4) * 8 + k];
                }
            }
        }
    }
    
    for (int i=0; i<m_nRounds - 1; i++) {
        for (int j = 0; j < BLOCK_BYTE_NUM; j++) {
            int bijMatIndex = j / 4 * 7 + 6;
            for (int k = 0;k < TABLE_8BIT_IN_SIZE; k++) {
                // R ^ -1
                BYTE input = (BYTE)k;
                
                if (this->use04table) {
                    input = byteMul2Mat(input,
                                        bij.x1[i][bijMatIndex][(j % 4) * 2].inv,
                                        bij.x1[i][bijMatIndex][(j % 4) * 2 + 1].inv);
                }
                
                //       32  x  1 = 32  x  8     mul 8 x 1
                matMulByte(temp1.B, partition[i][j], &input, 8);
                
                // L
                for (int m = 0; m < SECTION_BYTE_NUM ; m++) {
                    
                    //        8 x 1      =  8  x  8                              mul  8 x 1
                    matMulByte(&temp2.B[m], bij.lt[i+1][shiftRowOp[(j/4)*4 + m]].mb, &temp1.B[m], 8);
                }
                wtable.et3[i][j][k].l = temp2.l;
            }
        }
    }
}



template<keyLength L>
void WaesGenerator<L>::generateTableType4(WaesTables<L> &wtable, BijectionTables<L> &bij, bool isEncrypt){
    
    // Now compute cascade of XOR tables
    // We have 8*32 XOR tables, they sum T1: [01] [23] [45] [67] [89] [1011] [1213] [1415]
    //                                        0     1   2     3   4     5      6      7
    // The task is to connect                  \   /     \   /     \   /        \    /
    //                                         [0123]    [4567]   [891011]    [12131415]
    //                                            8         9        10          11
    //                                             \       /          \          /
    //                                              \     /            \        /
    //                                             [01234567]       [89101112131415]
    //                                                 12                 13
    //                                                  \                 /
    //                                                   \               /
    //                                                [0123456789101112131415]
    //                                                           14
    //
    WAES_TB_TYPE4 (&t0)  [2][15][32]        = wtable.ex0;
    WAES_TB_TYPE4 (&t423)[L / 32 + 5][12][8]= wtable.ex4t2t3;
    WAES_TB_TYPE4 (&t432)[L / 32 + 5][12][8]= wtable.ex4t3t2;
    WAES_TB_TYPE1 (&t1)  [2][16]            = wtable.et1;
    WAES_TB_TYPE2 (&t2)  [L / 32 + 5][16]   = wtable.et2;
    WAES_TB_TYPE3 (&t3)  [L / 32 + 5][16]   = wtable.et3;
    
    // encode t1a output
    for (int i = 0; i < BLOCK_BYTE_NUM; i++) {
        for (int k = 0; k < TABLE_8BIT_IN_SIZE; k++) {
            for (int j = 0; j < 16; j++) {  // 128 x 1  =  16 x 8
                
                t1[0][i][k].B[j] = byteMul2Mat( t1[0][i][k].B[j],
                                            bij.x0[0][i][j * 2    ].mb,
                                            bij.x0[0][i][j * 2 + 1].mb );
                
                t1[1][i][k].B[j] = byteMul2Mat( t1[1][i][k].B[j],
                                               bij.x0[1][i][j * 2    ].mb,
                                               bij.x0[1][i][j * 2 + 1].mb );
                
            }
            
        }
        
    }// encode t1a output
    
    // make t1a xor
    for (int level = 8, count = 0; level >= 1; count += level, level = level / 2){
        for (int i = 0; i < level; i++) {
            for ( int k = 0; k < 32; k++){
                makeXorTable(t0[0][count + i][k],
                             bij.x0[0][(count + i) * 2        ][k].inv,
                             bij.x0[0][(count + i) * 2 + 1    ][k].inv,
                             bij.x0[0][(level + count) * 2 + i][k].mb);
                
                makeXorTable(t0[1][count + i][k],
                             bij.x0[1][(count + i) * 2        ][k].inv,
                             bij.x0[1][(count + i) * 2 + 1    ][k].inv,
                             bij.x0[1][(level + count) * 2 + i][k].mb);
                                                     
            }
        }
    }// make t1a xor
    
    
    // make t2 t3 xor
    for (int r = 0; r < TEMPLATE_ROUND_NUM - 1; r++) {
        for (int i = 0; i < SECTION_NUM; i++) {
            // encode t2 output
            for (int j = 0; j < 4; j++) { // 4   32 x 4
                for ( int k = 0; k < TABLE_8BIT_IN_SIZE; k++){
                    
                    for (int m = 0; m < 4; m++) {
                        t2[r][i * 4 + j][k].B[m] = byteMul2Mat( t2[r][i * 4 + j][k].B[m],
                                                            bij.x1[r][i * 7 + j][m * 2].mb,
                                                            bij.x1[r][i * 7 + j][m * 2 + 1].mb);
                    }
                }
                
            }// encode t2 output
            
            // xor
            for (int j = 0; j < 8; j++) {
                makeXorTable(t423[r][i * 3 + 0][j],
                             bij.x1[r][i * 7 + 0][j].inv,
                             bij.x1[r][i * 7 + 1][j].inv,
                             bij.x1[r][i * 7 + 4][j].mb);
                makeXorTable(t423[r][i * 3 + 1][j],
                             bij.x1[r][i * 7 + 2][j].inv,
                             bij.x1[r][i * 7 + 3][j].inv,
                             bij.x1[r][i * 7 + 5][j].mb);
                makeXorTable(t423[r][i * 3 + 2][j],
                             bij.x1[r][i * 7 + 4][j].inv,
                             bij.x1[r][i * 7 + 5][j].inv,
                             bij.x1[r][i * 7 + 6][j].mb);
            }
        }
    }// make t2 t3 xor
    
    // make t3 t2 xor
    for (int r = 0; r < TEMPLATE_ROUND_NUM - 1; r++) {
        for (int i = 0; i < SECTION_NUM; i++) {
            // encode t2 output
            for (int j = 0; j < 4; j++) { // 4   32 x 4
                for ( int k = 0; k < TABLE_8BIT_IN_SIZE; k++){
                    
                    for (int m = 0; m < 4; m++) {
                        t3[r][i * 4 + j][k].B[m] = byteMul2Mat( t3[r][i * 4 + j][k].B[m],
                                                               bij.x2[r][i * 7 + j][m * 2].mb,
                                                               bij.x2[r][i * 7 + j][m * 2 + 1].mb);
                    }
                }
                
            }// encode t2 output
            
            // xor
            for (int j = 0; j < 8; j++) {
                makeXorTable(t432[r][i * 3 + 0][j],
                             bij.x2[r][i * 7 + 0][j].inv,
                             bij.x2[r][i * 7 + 1][j].inv,
                             bij.x2[r][i * 7 + 4][j].mb);
                makeXorTable(t432[r][i * 3 + 1][j],
                             bij.x2[r][i * 7 + 2][j].inv,
                             bij.x2[r][i * 7 + 3][j].inv,
                             bij.x2[r][i * 7 + 5][j].mb);
                makeXorTable(t432[r][i * 3 + 2][j],
                             bij.x2[r][i * 7 + 4][j].inv,
                             bij.x2[r][i * 7 + 5][j].inv,
                             bij.x2[r][i * 7 + 6][j].mb);
            }
        }
    }// make t3 t2 xor
}






template<keyLength L>
int  WaesGenerator<L>::generateKeyTables(const BYTE * key, WaesTables<L> &tables, bool isEncrypt){
    
    BijectionTables<L> bijtable;
    
    generateTMCtables(key, isEncrypt);
    
    generateRandomBijectionTables(bijtable);
    
    generateTableType1(tables, bijtable, isEncrypt);
    
    generateTableType2(tables, bijtable, isEncrypt);
    
    generateTableType3(tables, bijtable, isEncrypt);
    
    if (this->use04table) {
        generateTableType4(tables, bijtable, isEncrypt);
    }
    
    
    
    return 0;
}




template<keyLength L>
WaesGenerator<L>::WaesGenerator():m_nKeyIn32(L/32),m_nRounds(L/32+6),haveSetExEncoding(false){
    this->useIOident = false;
    this->use04ident = true;
    this->use08ident = true;
    this->use32ident = true;
    
    // whether or not use these nibble xor tables, for development use,
    // always set to true latter, because only set xor table is not enough
    // waes proccess also need to change.
    // but to make generate faster, remove this variable
    this->use04table = true;
}


////////////////////////////////////////////
//
//         const data section
//
////////////////////////////////////////////
template<keyLength L>
const int WaesGenerator<L>::m_nSection = 4;

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
const TB256 WaesGenerator<L>::sboxInv = {
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
const int WaesGenerator<L>::shiftRow[BLOCK_BYTE_NUM] = {
    0,  5, 10, 15,
    4,  9, 14,  3,
    8, 13,  2,  7,
    12, 1,  6, 11
};

template<keyLength L>
const int WaesGenerator<L>::shiftRowInv[BLOCK_BYTE_NUM] = {
    0, 13, 10,  7,
    4,  1, 14, 11,
    8,  5,  2, 15,
    12, 9,  6,  3
};

//
// 60,  61,  62,  63,                            60,  131, 202, 273
// 130, 131, 132, 133,  apart last, shiftrow     130, 201, 272, 63
// 200, 201, 202, 203,  -------------------->    200, 271, 62,  133
// 270, 271, 272, 273,                           270, 61,  132, 203
template<keyLength L>
const int WaesGenerator<L>::xorShiftRow1[16] = {
    6,  13, 20, 27,
    13, 20, 27, 6,
    20, 27, 6,  13,
    27, 6,  13, 20
};

template<keyLength L>
const int WaesGenerator<L>:: xorShiftRow2[16] = {
    0, 2, 4, 6,
    0, 2, 4, 6,
    0, 2, 4, 6,
    0, 2, 4, 6
};

//
//0  60,  61,  62,  63,                               60,  271, 202, 133
//4  130, 131, 132, 133,  apart last, shiftrowinv     130, 61,  272, 203
//8  200, 201, 202, 203,  ----------------------->    200, 131, 62,  273
//12 270, 271, 272, 273,                              270, 201, 132, 63
template<keyLength L>
const int WaesGenerator<L>::xorShiftRow1Decode[16] = {
    6,  27, 20, 13,
    13, 6,  27, 20,
    20, 13, 6,  27,
    27, 20, 13, 6
};

template<keyLength L>
const int WaesGenerator<L>:: xorShiftRow2Decode[16] = {
    0, 2, 4, 6,
    0, 2, 4, 6,
    0, 2, 4, 6,
    0, 2, 4, 6
};

template<keyLength L>
const int WaesGenerator<L>:: emptyMap[16] = {
    0, 1, 2, 3,
    4, 5, 6, 7,
    8, 9, 10,11,
    12,13,14,15
};

template<keyLength L>
const BYTE WaesGenerator<L>::mc[SECTION_NUM][SECTION_BYTE_NUM] = {
    {0x02, 0x01, 0x01, 0x03},
    {0x03, 0x02, 0x01, 0x01},
    {0x01, 0x03, 0x02, 0x01},
    {0x01, 0x01, 0x03, 0x02}
};
template<keyLength L>
const BYTE WaesGenerator<L>::mcInv[SECTION_NUM][SECTION_BYTE_NUM] = {
    {0x0e, 0x09, 0x0d, 0x0b},
    {0x0b, 0x0e, 0x09, 0x0d},
    {0x0d, 0x0b, 0x0e, 0x09},
    {0x09, 0x0d, 0x0b, 0x0e}
};
#endif /* defined(__whiteboxAes__waesGenerator__) */
