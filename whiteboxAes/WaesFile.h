//
//  WaesFile.h
//  whiteboxAes
//
//  Created by bryce on 15/5/30.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#ifndef __whiteboxAes__WaesFile__
#define __whiteboxAes__WaesFile__

#include "type.h"
#include <fstream>
#include <iostream>

class WaesFile{
    
public:
    
    template<keyLength L>
    int read( WaesTables<L> &wtable, const char* path);
    
    template<keyLength L>
    int write(const WaesTables<L> &wtable,  const char* path);
    
    template<keyLength L>
    int write(const WaesTablesShrankXor<L> &wtable,  const char* path);
    
    template<keyLength L>
    int read( WaesTablesShrankXor<L> &wtable, const char* path);
    
};

template<keyLength L>
int WaesFile::read( WaesTables<L> &wtable, const char* path){
    
    ifstream inFile (path, ios::in|ios::binary);
    if (!inFile) {
        cout << "Can not open file " << path << "\n";
        return 1;
    }
    WaesTables<L> *table [2];
    table[0] = &wtable;
//    table[1] = &dt;
    for (int i=0; i<1; i++) {
    
        //inFile.read((char*)table[i]->ex0, 2 * 15 * 32 * xorTableSize);  //245760,240K
        inFile.read((char*)table[i]->ex0, sizeof(table[i]->ex0));
        
        //length = 2 * 16 * 256 * 16;
        //inFile.read((char*)table[i]->et1, 2 * 16 * xorTableSize * 16); //131072,128K
        inFile.read((char*)table[i]->et1, sizeof(table[i]->et1));
        
        //length = (L/32+5) * 16 * 256 * 4;
        //inFile.read((char*)table[i]->et2, (L/32+5) * 16 * 256 * 4); //147456, 114K
        inFile.read((char*)table[i]->et2, sizeof(table[i]->et2));
        
        //length = (L/32+5) * 16 * 256 * 4;
        //inFile.read((char*)table[i]->et3, (L/32+5) * 16 * 256 * 4); //147456, 114K
        inFile.read((char*)table[i]->et3, sizeof(table[i]->et3));
        
        //length = (L/32+5) * 12 * 8;
        //inFile.read((char*)table[i]->ex4t2t3, (L/32+5) * 12 * 8 * 256); // 221184, 216K
        inFile.read((char*)table[i]->ex4t2t3, sizeof(table[i]->ex4t2t3));
        
        //length = (L/32+5) * 12 * 8;
        //inFile.read((char*)table[i]->ex4t3t2, (L/32+5) * 12 * 8 * xorTableSize); //221184, 216K
        inFile.read((char*)table[i]->ex4t3t2, sizeof(table[i]->ex4t3t2));
    }
    
    inFile.close();
    return 0;
}


template<keyLength L>
int WaesFile::write(const WaesTables<L> &wtable, const char* path){
    
    ofstream outFile (path, ios::out|ios::binary|ios::trunc);
    if (!outFile) {
        cout << "Can not open file " << path << "\n";
        return 1;
    }
    
    const WaesTables<L> * table [2];
    table[0] = &wtable;
//    table[1] = &dt;
    
    for (int i=0; i<1; i++) {
        //length = 2 * 15 * 32 * 256;
        //outFile.write((char*)table[i]->ex0, 2 * 15 * 32 * xorTableSize);
        outFile.write((char*)table[i]->ex0, sizeof(table[i]->ex0));
        
        //length = 2 * 16 * 256 * 16;
        //outFile.write((char*)table[i]->et1, 2 * 16 * 256 * 16);
        outFile.write((char*)table[i]->et1, sizeof(table[i]->et1));
        
        //length = (L/32+5) * 16 * 256 * 4;
        //outFile.write((char*)table[i]->et2, (L/32+5) * 16 * 256 * 4);
        outFile.write((char*)table[i]->et2, sizeof(table[i]->et2));
        
        //length = (L/32+5) * 16 * 256 * 4;
        //outFile.write((char*)table[i]->et3, (L/32+5) * 16 * 256 * 4);
        outFile.write((char*)table[i]->et3, sizeof(table[i]->et3));
        
        //length = (L/32+5) * 12 * 8;
        //outFile.write((char*)table[i]->ex4t2t3, (L/32+5) * 12 * 8 * xorTableSize);
        outFile.write((char*)table[i]->ex4t2t3, sizeof(table[i]->ex4t2t3));
        
        //length = (L/32+5) * 12 * 8;
        //outFile.write((char*)table[i]->ex4t3t2, (L/32+5) * 12 * 8 * xorTableSize);
        outFile.write((char*)table[i]->ex4t3t2, sizeof(table[i]->ex4t3t2));
    }

    outFile.close();
    
    return 0;
}


template<keyLength L>
int WaesFile::read( WaesTablesShrankXor<L> &wtable, const char* path){
    
    ifstream inFile (path, ios::in|ios::binary);
    if (!inFile) {
        cout << "Can not open file " << path << "\n";
        return 1;
    }
    WaesTablesShrankXor<L> *table [2];
    table[0] = &wtable;
    //    table[1] = &dt;
    for (int i=0; i<1; i++) {
        
        
        inFile.read((char*)table[i]->ex0, sizeof(table[i]->ex0));
        
        inFile.read((char*)table[i]->et1, sizeof(table[i]->et1));
        
        inFile.read((char*)table[i]->et2, sizeof(table[i]->et2));
        
        inFile.read((char*)table[i]->et3, sizeof(table[i]->et3));
        
        inFile.read((char*)table[i]->ex4t2t3, sizeof(table[i]->ex4t2t3));
        
        inFile.read((char*)table[i]->ex4t3t2, sizeof(table[i]->ex4t3t2));
    }
    
    inFile.close();
    return 0;
}

template<keyLength L>
int WaesFile::write(const WaesTablesShrankXor<L> &wtable, const char* path){
    ofstream outFile (path, ios::out|ios::binary|ios::trunc);
    if (!outFile) {
        cout << "Can not open file " << path << "\n";
        return 1;
    }
    const WaesTablesShrankXor<L> * table [2];
    table[0] = &wtable;
    for (int i=0; i<1; i++) {
        
        outFile.write((char*)table[i]->ex0, sizeof(table[i]->ex0));
        
        
        outFile.write((char*)table[i]->et1, sizeof(table[i]->et1));
        
        
        outFile.write((char*)table[i]->et2, sizeof(table[i]->et2));
        
        
        outFile.write((char*)table[i]->et3, sizeof(table[i]->et3));
        
        
        outFile.write((char*)table[i]->ex4t2t3, sizeof(table[i]->ex4t2t3));
        
        
        outFile.write((char*)table[i]->ex4t3t2, sizeof(table[i]->ex4t3t2));
    }
    
    outFile.close();
    
    return 0;
}
#endif /* defined(__whiteboxAes__WaesFile__) */
