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
    
    //Nb Number of columns (32-bit words) comprising the State. For this standard, Nb = 4.
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
    
    static const int map[16] = {
        0, 5, 10,15,
        4, 9, 14,3,
        8, 13,2, 7,
        12,1, 6, 11
    };
    
    W128b state, t1bres;
    W32b t2res[16];
    
    W128CP(in, state);
    
    // round 1 - 9
    for (int r=0; r<m_nRounds-1; r++) {
        for (int j=0; j<N_BYTES; j+=4) {
            
            t2res[j+0].l = keyTable.et2[r][j+0][state.B[map[j+0]]].l;
            t2res[j+1].l = keyTable.et2[r][j+1][state.B[map[j+1]]].l;
            t2res[j+2].l = keyTable.et2[r][j+2][state.B[map[j+2]]].l;
            t2res[j+3].l = keyTable.et2[r][j+3][state.B[map[j+3]]].l;
            t2res[j+0].l = t2res[j+0].l ^ t2res[j+1].l ^ t2res[j+2].l ^ t2res[j+3].l;
        }
        
        for (int j=0; j<m_nSection; j++) {
            state.l[j] = t2res[j*4].l;
        }
    }
    
    // final round
    for (int j=0; j<N_BYTES; j++) {
        t1bres.B[j] = keyTable.tbox10[j][state.B[map[j]]];
    }
    for (int j=0; j<N_BYTES; j++) {
        state.B[j] = t1bres.B[j];
    }
    
    // out
    for (int i=0; i<16; i++) {
        out[i] = state.B[i];
    }
}
#endif
