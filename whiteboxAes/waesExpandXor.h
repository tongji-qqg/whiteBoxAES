#ifndef __WAES_EXPAND_XOR_H__
#define __WAES_EXPAND_XOR_H__

# include "waesBase.h"

//
// WAES 声明


template<keyLength L>
class WAESEX: public WAES_BASE<L>{
    
private:
    
    void eliminateExteranlEncodingInit(BYTE *key);
    
    WaesFile wfile;
    
    WaesTables<L> enKeyTable, deKeyTable;
public:
    
    
    void cypherBlock(W128b &in, BYTE *out, bool isEncrypt = true);

    WAESEX(const BYTE* key);
    
    WAESEX(const char* path, bool isEncrypt = true);
    
    WAESEX(const char* enPath, const char* dePath);
    
    int saveKey2File(const char* path, bool isEncrypt=true);
    
    int loadKeyFromFile(const char* path, bool isEncrypt=true);
};


template<keyLength L>
WAESEX<L>::WAESEX(const BYTE* key){
    this->baseInit();
    
    this->eliminateExteranlEncodingInit(key);
}


template<keyLength L>
WAESEX<L>::WAESEX(const char* path, bool isEncrypt){
    this->baseInit();
    
    if (isEncrypt) {
        this->loadKeyFromFile(path);
    }else{
        this->loadKeyFromFile(path, false);
    }
}

template<keyLength L>
WAESEX<L>::WAESEX(const char * enPath, const char* dePath){
    this->baseInit();
    
    this->loadKeyFromFile(enPath);
    
    this->loadKeyFromFile(dePath, false);
}


template<keyLength L>
int WAESEX<L>::saveKey2File(const char* path, bool isEncrypt){
    
    
    if (true == isEncrypt && this->initEnKeyTable == true) {
        
        return wfile.write(this->enKeyTable, path);
    }
    
    if (false == isEncrypt && this->initDeKeyTable) {
        
        return wfile.write(this->deKeyTable, path);
    }
    return -1;
}



template<keyLength L>
int WAESEX<L>::loadKeyFromFile(const char* path, bool isEncrypt){
    
    
    if (true == isEncrypt && 0 == wfile.read (this->enKeyTable, path)) {
        
        this->initEnKeyTable = true;
        return 0;
    }
    if (false == isEncrypt && 0 == wfile.read (this->deKeyTable, path)) {
        
        this->initDeKeyTable = true;
        return 0;
    }
    
    return 1;
}



template<keyLength L>
void WAESEX<L>::eliminateExteranlEncodingInit(BYTE *key){
    WaesGenerator<L> gen;
    
    
    randomMixingBijection(this->f, 128);
    randomMixingBijection(this->g, 128);
    NTL::inv(this->fi, this->f);NTL::inv(this->gi,this->g);
    
    
    gen.setExternalEncoding(this->f,this->g);
    
    gen.generateKeyTables(key,this->enKeyTable);
    
    this->initEnKeyTable = true;
    
    gen.setExternalEncoding(this->gi, this->fi);
    
    gen.generateKeyTables(key,this->deKeyTable,false);
    
    this->initDeKeyTable = true;
    
}



// process a block
template<keyLength L>
void WAESEX<L>::cypherBlock(W128b &in, BYTE *out, bool isEncrypt){
    
    static const int shiftRow[BLOCK_BYTE_NUM] = {
        0, 5, 10,15,
        4, 9, 14,3,
        8, 13,2, 7,
        12,1, 6, 11
    };
    static const int shiftRowInv[BLOCK_BYTE_NUM] = {
        0, 13, 10,  7,
        4,  1, 14, 11,
        8,  5,  2, 15,
        12, 9,  6,  3
    };
    WaesTables<L> & keyTable                 = isEncrypt ? this->enKeyTable: this->deKeyTable;
    const int (&shiftRowOp)[BLOCK_BYTE_NUM]  = isEncrypt ? shiftRow        : shiftRowInv;
    
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
    
    
    //for (int i=1; i<16; i++) {
        //W128bXor(t1ares[0], t1ares[0], t1ares[i]);
    //}
    
    W128CP(t1ares[0], state);

    //matShow(state.B);
    
    // round 1 - 9
    for (int r=0; r<this->m_nRounds-1; r++) {
        // apply t2 tables
        for (int j=0; j<BLOCK_BYTE_NUM; j+=4) {
            t2res[j+0].l = keyTable.et2[r][j+0][state.B[shiftRowOp[j+0]]].l;
            t2res[j+1].l = keyTable.et2[r][j+1][state.B[shiftRowOp[j+1]]].l;
            t2res[j+2].l = keyTable.et2[r][j+2][state.B[shiftRowOp[j+2]]].l;
            t2res[j+3].l = keyTable.et2[r][j+3][state.B[shiftRowOp[j+3]]].l;
            
            // not xor table now
            // t2res[j+0].l = t2res[j+0].l ^ t2res[j+1].l ^ t2res[j+2].l ^ t2res[j+3].l;
            W32bXor(t2res[j + 0], t2res[j + 0], t2res[j + 1], keyTable.ex4t2t3[r][j/4*3+0]);
            W32bXor(t2res[j + 2], t2res[j + 2], t2res[j + 3], keyTable.ex4t2t3[r][j/4*3+1]);
            W32bXor(t2res[j + 0], t2res[j + 0], t2res[j + 2], keyTable.ex4t2t3[r][j/4*3+2]);
        }
        
        for (int j=0; j<this->m_nSection; j++) {
            state.l[j] = t2res[j*4].l;
        }
        
        //std::cout << "shiftrow,subbyte,shiftrow" << "\n";
        //matShow(state.B);
        
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
        
        for (int j=0; j<this->m_nSection; j++) {
            state.l[j] = t2res[j*4].l;
        }
        //matShow(state.B);
    }
    
    //matShow(state.B);
    
    // final round
    for (int j=0; j<BLOCK_BYTE_NUM; j++) {
        //t1bres[0].B[j] = keyTable.tbox10[j][state.B[map[j]]];
        //t1bres[0].B[j] = keyTable.et1[1][j][state.B[map[j]]].B[0];
        W128CP(keyTable.et1[1][j][state.B[shiftRowOp[j]]], t1bres[j]);
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
    
    
    //for (int i=1; i<16; i++) {
        //W128bXor(t1bres[0], t1bres[0], t1bres[i]);
    //}
    W128CP(t1bres[0],state);
    
    // out
    for (int i=0; i<16; i++) {
        out[i] = state.B[i];
    }
}

// old decryptBlock, i use this to debug the  WAES
// reserve here for future use
// i spent more than 4 hour to find the bug, it turns out small
// 1. t1a add round key i write + instead of ^
// i should be more careful
//
//
//template<keyLength L>
//int WAES<L>::decrypt(BYTE *in, BYTE *out, int blockSize){
//    static const int shiftRowInv[BLOCK_BYTE_NUM] = {
//        0, 13, 10,  7,
//        4,  1, 14, 11,
//        8,  5,  2, 15,
//        12, 9,  6,  3
//    };
//    W128b state;
//    BYTE temp[16];
//    W32b ty[4];
//    
//    for(int i=0;i<16;i++)
//        state.B[i] = in[i] ;
//    //matShow(state.B);
//    //matShow(deKeyTable.m_roundKey+160);
//    for (int i=0; i<16; i++) {
//        state.B[i] ^=this->deKeyTable.m_roundKey[160 + i];
//    }
//    
//    for (int r=m_nRounds - 1; r > 0; r--) {
//        std::cout << r << "\n";
//        //matShow(state.B);
//        //std::cout << "roundkey" << "\n";
//        //matShow(m_w + (i+1)*16 );
//        
//        for (int i=0; i<16; i++) {
//            temp[i] = state.B[i];
//        }
//        for (int i=0; i<16; i++) {
//            state.B[i] = temp[ shiftRowInv[i] ];
//        }
//        //std::cout << "shiftrow" << "\n";
//        //matShow(state.B);
//        
//        for (int i=0; i<16; i++) {
//            state.B[i] = deKeyTable.tbox[r][i][ state.B[i] ];
//        }
//        
//        std::cout << "shiftrow,subbyte,shiftrow" << "\n";
//        matShow(state.B);
//        
//        for (int i=0; i<16; i+=4) {
//            
//            ty[0].l = deKeyTable.tybox[0][ state.B[i + 0] ].l;
//            ty[1].l = deKeyTable.tybox[1][ state.B[i + 1] ].l;
//            ty[2].l = deKeyTable.tybox[2][ state.B[i + 2] ].l;
//            ty[3].l = deKeyTable.tybox[3][ state.B[i + 3] ].l;
//            
//            ty[0].l = ty[0].l ^ ty[1].l ^ ty[2].l ^ ty[3].l;
//            
//            state.B[i + 0] = ty[0].B[0];
//            state.B[i + 1] = ty[0].B[1];
//            state.B[i + 2] = ty[0].B[2];
//            state.B[i + 3] = ty[0].B[3];
//        }
//        
//        std::cout << "mixcol" << "\n";
//        matShow(state.B);
//    }
//    
//    for (int i=0; i<16; i++) {
//        temp[i] = state.B[i];
//    }
//    for (int i=0; i<16; i++) {
//        state.B[i] = temp[ shiftRowInv[i] ];
//    }
//    
//    for (int i=0; i<16; i++) {
//        state.B[i] = deKeyTable.tbox[0][i][ state.B[i] ];
//    }
//    
//    // out
//    for (int i=0; i<16; i++) {
//        out[i] = state.B[i];
//    }
//    return 0;
//}
#endif
