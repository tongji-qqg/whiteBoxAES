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
    int read( WaesTables<L> &et,  WaesTables<L> &dt, const char* path);
    
    template<keyLength L>
    int write(const WaesTables<L> &et, const WaesTables<L> &dt, const char* path);
    
};

template<keyLength L>
int WaesFile::read( WaesTables<L> &et,  WaesTables<L> &dt, const char* path){
    
    ifstream inFile (path, ios::in|ios::binary);
    if (!inFile) {
        cout << "Can not open file " << path << "\n";
        return 1;
    }
    WaesTables<L> *table [2];
    table[0] = &et;
    table[1] = &dt;
    for (int i=0; i<2; i++) {
        
        inFile.read((char*)table[i]->ex0, 2 * 15 * 32 * 256);
        
        //length = 2 * 16 * 256 * 16;
        //prepare((char*)table.et1, length);
        inFile.read((char*)table[i]->et1, 2 * 16 * 256 * 16);
        
        //length = (L/32+5) * 16 * 256 * 4;
        //prepare((char*)table.et2, length);
        inFile.read((char*)table[i]->et2, (L/32+5) * 16 * 256 * 4);
        
        //length = (L/32+5) * 16 * 256 * 4;
        //prepare((char*)table.et3, length);
        inFile.read((char*)table[i]->et3, (L/32+5) * 16 * 256 * 4);
        
        //length = (L/32+5) * 12 * 8;
        //prepare((char*)table.ex4t2t3, length);
        inFile.read((char*)table[i]->ex4t2t3, (L/32+5) * 12 * 8 * 256);
        
        //length = (L/32+5) * 12 * 8;
        //prepare((char*)table.ex4t3t2, length);
        inFile.read((char*)table[i]->ex4t3t2, (L/32+5) * 12 * 8 * 256);
    }
    
    
    inFile.close();
    return 0;
}


template<keyLength L>
int WaesFile::write(const WaesTables<L> &et, const WaesTables<L> &dt, const char* path){
    
    ofstream outFile (path, ios::out|ios::binary|ios::trunc);
    if (!outFile) {
        cout << "Can not open file " << path << "\n";
        return 1;
    }
    
    const WaesTables<L> * table [2];
    table[0] = &et;
    table[1] = &dt;
    
    for (int i=0; i<2; i++) {
        //length = 2 * 15 * 32 * 256;
        //prepare((char*)table.ex0, length);
        outFile.write((char*)table[i]->ex0, 2 * 15 * 32 * 256);
        
        //length = 2 * 16 * 256 * 16;
        //prepare((char*)table.et1, length);
        outFile.write((char*)table[i]->et1, 2 * 16 * 256 * 16);
        
        //length = (L/32+5) * 16 * 256 * 4;
        //prepare((char*)table.et2, length);
        outFile.write((char*)table[i]->et2, (L/32+5) * 16 * 256 * 4);
        
        //length = (L/32+5) * 16 * 256 * 4;
        //prepare((char*)table.et3, length);
        outFile.write((char*)table[i]->et3, (L/32+5) * 16 * 256 * 4);
        
        //length = (L/32+5) * 12 * 8;
        //prepare((char*)table.ex4t2t3, length);
        outFile.write((char*)table[i]->ex4t2t3, (L/32+5) * 12 * 8 * 256);
        
        //length = (L/32+5) * 12 * 8;
        //prepare((char*)table.ex4t3t2, length);
        outFile.write((char*)table[i]->ex4t3t2, (L/32+5) * 12 * 8 * 256);
    }
    

    outFile.close();
    
    return 0;
}
#endif /* defined(__whiteboxAes__WaesFile__) */
