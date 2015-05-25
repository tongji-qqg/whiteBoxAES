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
};


template<keyLength L>
const int WAES<L>::m_nSection = 4;


// init, set lookup tables using generator, may read from somewhere afterwards
template<keyLength L>
WAES<L>::WAES(BYTE* key):m_nRounds(L/32+6){
    
    WaesGenerator<L> gen;
    
    gen.generateKeyTables(key,this->keyTable);
    
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
    
    W128b state;
    W128b ares[16];
    W32b res[16];
    
    W128CP(state, in);
    for (int r=0; r<m_nRounds-1; r++) {
        for (int j=0; j<N_BYTES; j+=4) {
            res[j+0].l = keyTable.et2[r][j+0][state.B[map[j+0]]].l;
            res[j+1].l = keyTable.et2[r][j+1][state.B[map[j+1]]].l;
            res[j+2].l = keyTable.et2[r][j+2][state.B[map[j+2]]].l;
            res[j+3].l = keyTable.et2[r][j+3][state.B[map[j+3]]].l;
            
            res[j+0].l = res[j+0].l ^ res[j+1].l ^ res[j+2].l ^ res[j+3].l;
        }
        
        for (int j=0; j<m_nSection; j++) {
            state.l[j] = res[j*4].l;
        }
        matShow(state.B);
    }
    
    
    for (int j=0; j<N_BYTES; j++) {
        //W128CP(ares[j], keyTable.et1[1][j][in.B[map[j]]]);
        ares[0].B[j] = keyTable.tbox10[j][state.B[map[j]]];
    }
    for (int j=0; j<N_BYTES; j++) {
        state.B[j] = ares[0].B[j];
    }
    for (int j=0; j<4; j++) {
        for (int k=0; k<16; k++) {
            //state.l[j] ^= ares[k].l[j];
        }
        
    }
    
    for (int i=0; i<16; i++) {
        out[i] = state.B[i];
    }
}
#endif
