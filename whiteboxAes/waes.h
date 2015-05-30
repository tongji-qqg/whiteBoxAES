#ifndef __WAES_H__
#define __WAES_H__

# include "type.h"
# include "util.h"
# include "waesGenerator.h"

//
// WAES 声明

template<keyLength L>
class WAES{
    
private:
    
    //Nb Number of columns (32-bit words) comprising the State. For this standard = 4.
    static const int m_nSection;
    
    //Nr Number of rounds, which is a function of Nk and Nb (which isfixed). For this standard, Nr = 10, 12, or 14.
    int m_nRounds;
    
    WaesTables<L> keyTable;  // all look up tables
    
public:
	WAES(BYTE* key);
    
    ~WAES(){};
	
    void encryptBlock(W128b &in, BYTE * out);
    
    void mixColumns(W128b &state);
};


template<keyLength L>
const int WAES<L>::m_nSection = 4;


// init, set lookup tables using generator, may read from somewhere afterwards
template<keyLength L>
WAES<L>::WAES(BYTE* key):m_nRounds(L/32+6){
    
    WaesGenerator<L> gen;
    
    gen.generateKeyTables(key,this->keyTable);
    
}

template<keyLength L>
void WAES<L>::mixColumns(W128b &state){
    
    static const BYTE mc[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}};
    
    BYTE  res[4];
    
    for (int i = 0; i < 4; i++) {
        
        for(int j=0;j<4;j++){
            res[j] = gmult(mc[j][0], state.B[i * 4 + 0])^
            gmult(mc[j][1], state.B[i * 4 + 1])^
            gmult(mc[j][2], state.B[i * 4 + 2])^
            gmult(mc[j][3], state.B[i * 4 + 3]);
        }
        
        for (int j = 0; j < 4; j++) {
            state.B[i * 4 + j] = res[j];
        }
    }
}

// process a block
template<keyLength L>
void WAES<L>::encryptBlock(W128b &in, BYTE *out){
    
    static const int map[BLOCK_BYTE_NUM] = {
        0, 5, 10,15,
        4, 9, 14,3,
        8, 13,2, 7,
        12,1, 6, 11
    };
    
    W128b state,t1ares[BLOCK_BYTE_NUM], t1bres[BLOCK_BYTE_NUM];
    W32b t2res[16];
    
    // input decoding
    for (int i=0; i<BLOCK_BYTE_NUM; i++) {
        W128CP(keyTable.et1[0][i][in.B[i]], t1ares[i]);
    }
    for (int i=0; i<8; i++) {
        W128bXor(t1ares[i*2], t1ares[i*2], t1ares[i*2+1], keyTable.ex0[0][i]);
    }
    for (int i=0; i<4; i++) {
        W128bXor(t1ares[i*4], t1ares[i*4], t1ares[i*4+2], keyTable.ex0[0][8+i]);
    }
    for (int i=0; i<2; i++) {
        W128bXor(t1ares[i*8], t1ares[i*8], t1ares[i*8+4], keyTable.ex0[0][12+i]);
    }
    W128bXor(t1ares[0], t1ares[0], t1ares[8], keyTable.ex0[0][14]);
    
    for (int i=1; i<16; i++) {
        //W128bXor(t1ares[0], t1ares[0], t1ares[i]);
    }
    
    W128CP(t1ares[0], state);
    
    //matShow(state.B);
    // round 1 - 9
    for (int r=0; r<m_nRounds-1; r++) {
        // apply t2 tables
        for (int j=0; j<BLOCK_BYTE_NUM; j+=4) {
            t2res[j+0].l = keyTable.et2[r][j+0][state.B[map[j+0]]].l;
            t2res[j+1].l = keyTable.et2[r][j+1][state.B[map[j+1]]].l;
            t2res[j+2].l = keyTable.et2[r][j+2][state.B[map[j+2]]].l;
            t2res[j+3].l = keyTable.et2[r][j+3][state.B[map[j+3]]].l;
            
            // not xor table now
            // t2res[j+0].l = t2res[j+0].l ^ t2res[j+1].l ^ t2res[j+2].l ^ t2res[j+3].l;
            W32bXor(t2res[j + 0], t2res[j + 0], t2res[j + 1], keyTable.ex4t2t3[r][j/4*3+0]);
            W32bXor(t2res[j + 2], t2res[j + 2], t2res[j + 3], keyTable.ex4t2t3[r][j/4*3+1]);
            W32bXor(t2res[j + 0], t2res[j + 0], t2res[j + 2], keyTable.ex4t2t3[r][j/4*3+2]);
        }
        
        for (int j=0; j<m_nSection; j++) {
            state.l[j] = t2res[j*4].l;
        }
        
        // apply t3 tables;
        for (int j=0; j<BLOCK_BYTE_NUM; j+=4) {
            
            t2res[j+0].l = keyTable.et3[r][j+0][state.B[j+0]].l;
            t2res[j+1].l = keyTable.et3[r][j+1][state.B[j+1]].l;
            t2res[j+2].l = keyTable.et3[r][j+2][state.B[j+2]].l;
            t2res[j+3].l = keyTable.et3[r][j+3][state.B[j+3]].l;
            
            // not xor table now
            //t2res[j+0].l = t2res[j+0].l ^ t2res[j+1].l ^ t2res[j+2].l ^ t2res[j+3].l;
            W32bXor(t2res[j + 0], t2res[j + 0], t2res[j + 1], keyTable.ex4t3t2[r][j/4*3+0]);
            W32bXor(t2res[j + 2], t2res[j + 2], t2res[j + 3], keyTable.ex4t3t2[r][j/4*3+1]);
            W32bXor(t2res[j + 0], t2res[j + 0], t2res[j + 2], keyTable.ex4t3t2[r][j/4*3+2]);
        }
        
        for (int j=0; j<m_nSection; j++) {
            state.l[j] = t2res[j*4].l;
        }
        //matShow(state.B);
    }
    
    matShow(state.B);
    
    // final round
    for (int j=0; j<BLOCK_BYTE_NUM; j++) {
        //t1bres[0].B[j] = keyTable.tbox10[j][state.B[map[j]]];
        //t1bres[0].B[j] = keyTable.et1[1][j][state.B[map[j]]].B[0];
        W128CP(keyTable.et1[1][j][state.B[map[j]]], t1bres[j]);
    }
    
    for (int i=0; i<8; i++) {
        W128bXor(t1bres[i*2], t1bres[i*2], t1bres[i*2+1], keyTable.ex0[1][i]);
    }
    for (int i=0; i<4; i++) {
        W128bXor(t1bres[i*4], t1bres[i*4], t1bres[i*4+2], keyTable.ex0[1][8+i]);
    }
    for (int i=0; i<2; i++) {
        W128bXor(t1bres[i*8], t1bres[i*8], t1bres[i*8+4], keyTable.ex0[1][12+i]);
    }
    W128bXor(t1bres[0], t1bres[0], t1bres[8], keyTable.ex0[1][14]);
    
    
    for (int i=1; i<16; i++) {
        //W128bXor(t1bres[0], t1bres[0], t1bres[i]);
    }
    W128CP(t1bres[0],state);
    
    // out
    for (int i=0; i<16; i++) {
        out[i] = state.B[i];
    }
}
#endif
