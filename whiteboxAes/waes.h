//
//  waesShrankXor.h
//  whiteboxAes
//
//  Created by bryce on 15/6/2.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#ifndef whiteboxAes_waes_h
#define whiteboxAes_waes_h

#include "waesBase.h"

template<keyLength L>
class WAES : public WAES_BASE<L>{
    
private:
    
    void eliminateExteranlEncodingInit(const BYTE *key);
    
    WaesFile wfile;
    
    WaesTablesShrankXor<L> enKeyTable, deKeyTable;
    
public:
    
    void cypherBlock(W128b &in, BYTE *out, bool isEncrypt = true);
    
    WAES(const BYTE* key);
    
    WAES(const char* path, bool isEncrypt);
    
    WAES(const char* enPath, const char* dePath);
    
    WAES(const BYTE* key, NTL::mat_GF2& f, NTL::mat_GF2 &g);
    
    int saveKey2File(const char* path, bool isEncrypt=true);
    
    int loadKeyFromFile(const char* path, bool isEncrypt=true);
    
};


// for test use,
// or for only 2 external exconding f*En()*g,g-1*De()*f-1,
// random generate one
template<keyLength L>
WAES<L>::WAES(const BYTE* key){
    this->baseInit();
    
    this->eliminateExteranlEncodingInit(key);
}




template<keyLength L>
WAES<L>::WAES(const char* path, bool isEncrypt){
    this->baseInit();
    
    if (isEncrypt) {
        this->loadKeyFromFile(path);
    }else{
        this->loadKeyFromFile(path, false);
    }
}



template<keyLength L>
WAES<L>::WAES(const char * enPath, const char* dePath){
    this->baseInit();
    
    this->loadKeyFromFile(enPath);
    
    this->loadKeyFromFile(dePath, false);
}


// for test use
// or for generate table with external encoding
template<keyLength L>
WAES<L>::WAES(const BYTE* key, NTL::mat_GF2& _f, NTL::mat_GF2 &_g){
    this->baseInit();
    
    WaesGenerator<L> gen;
    
    this->f = _f;
    this->g = _g;
    NTL::inv(this->fi, _f);
    NTL::inv(this->gi, _g);
    
    gen.setExternalEncoding(this->f,this->g);
    
    gen.generateKeyTablesAndShrankXor(key,this->enKeyTable);
    
    this->initEnKeyTable = true;
    
    gen.setExternalEncoding(this->gi, this->fi);
    
    gen.generateKeyTablesAndShrankXor(key,this->deKeyTable,false);
    
    this->initDeKeyTable = true;
}



template<keyLength L>
int WAES<L>::saveKey2File(const char* path, bool isEncrypt){
    
    
    if (true == isEncrypt && this->initEnKeyTable == true) {
        
        return wfile.write(this->enKeyTable, path);
    }
    
    if (false == isEncrypt && this->initDeKeyTable) {
        
        return wfile.write(this->deKeyTable, path);
    }
    return -1;
}



template<keyLength L>
int WAES<L>::loadKeyFromFile(const char* path, bool isEncrypt){
    
    
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
void WAES<L>::eliminateExteranlEncodingInit(const BYTE *key){
    WaesGenerator<L> gen;
    
    
    randomMixingBijection(this->f, 128);
    randomMixingBijection(this->g, 128);
    NTL::inv(this->fi, this->f);NTL::inv(this->gi,this->g);
    
    
    gen.setExternalEncoding(this->f,this->g);
    
    gen.generateKeyTablesAndShrankXor(key,this->enKeyTable);
    
    this->initEnKeyTable = true;
    
    gen.setExternalEncoding(this->gi, this->fi);
    
    gen.generateKeyTablesAndShrankXor(key,this->deKeyTable,false);
    
    this->initDeKeyTable = true;
    
}



// process a block
template<keyLength L>
void WAES<L>::cypherBlock(W128b &in, BYTE *out, bool isEncrypt){
    
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
    WaesTablesShrankXor<L> & keyTable        = isEncrypt ? this->enKeyTable: this->deKeyTable;
    const int (&shiftRowOp)[BLOCK_BYTE_NUM]  = isEncrypt ? shiftRow        : shiftRowInv;
    
    W128b state,t1ares[BLOCK_BYTE_NUM], t1bres[BLOCK_BYTE_NUM];
    W32b t2res[16];
    
    // input decoding
    for (int i=0; i<BLOCK_BYTE_NUM; i++) {
        W128CP(keyTable.et1[0][i][in.B[i]], t1ares[i]);
    }
    for (int i=0; i<8; i++) {
        W128bShrankXor(t1ares[i*2], t1ares[i*2], t1ares[i*2+1], keyTable.ex0[0][i]);
    }
    for (int i=0; i<4; i++) {
        W128bShrankXor(t1ares[i*4], t1ares[i*4], t1ares[i*4+2], keyTable.ex0[0][8+i]);
    }
    for (int i=0; i<2; i++) {
        W128bShrankXor(t1ares[i*8], t1ares[i*8], t1ares[i*8+4], keyTable.ex0[0][12+i]);
    }
    W128bShrankXor(t1ares[0], t1ares[0], t1ares[8], keyTable.ex0[0][14]);
    
    
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
            W32bShrankXor(t2res[j + 0], t2res[j + 0], t2res[j + 1], keyTable.ex4t2t3[r][j/4*3+0]);
            W32bShrankXor(t2res[j + 2], t2res[j + 2], t2res[j + 3], keyTable.ex4t2t3[r][j/4*3+1]);
            W32bShrankXor(t2res[j + 0], t2res[j + 0], t2res[j + 2], keyTable.ex4t2t3[r][j/4*3+2]);
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
            W32bShrankXor(t2res[j + 0], t2res[j + 0], t2res[j + 1], keyTable.ex4t3t2[r][j/4*3+0]);
            W32bShrankXor(t2res[j + 2], t2res[j + 2], t2res[j + 3], keyTable.ex4t3t2[r][j/4*3+1]);
            W32bShrankXor(t2res[j + 0], t2res[j + 0], t2res[j + 2], keyTable.ex4t3t2[r][j/4*3+2]);
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
        W128bShrankXor(t1bres[i*2], t1bres[i*2], t1bres[i*2+1], keyTable.ex0[1][i]);
    }
    for (int i=0; i<4; i++) {
        W128bShrankXor(t1bres[i*4], t1bres[i*4], t1bres[i*4+2], keyTable.ex0[1][8+i]);
    }
    for (int i=0; i<2; i++) {
        W128bShrankXor(t1bres[i*8], t1bres[i*8], t1bres[i*8+4], keyTable.ex0[1][12+i]);
    }
    W128bShrankXor(t1bres[0], t1bres[0], t1bres[8], keyTable.ex0[1][14]);
    
    
    //for (int i=1; i<16; i++) {
    //W128bXor(t1bres[0], t1bres[0], t1bres[i]);
    //}
    W128CP(t1bres[0],state);
    
    // out
    for (int i=0; i<16; i++) {
        out[i] = state.B[i];
    }
}
#endif
