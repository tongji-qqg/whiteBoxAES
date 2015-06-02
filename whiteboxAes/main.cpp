//
//  main.cpp
//  whiteboxAes
//
//  Created by bryce on 15/5/23.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#include <iostream>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <algorithm>
#include <string>

// NTL dependencies
#include <NTL/GF2.h>
#include <NTL/mat_GF2.h>

// Local dependencies
#include "aes.h"
#include "waes.h"
#include "waesExpandXor.h"
#include "waesGenerator.h"
#include "bijection.h"
#include "test.h"

#define CMD_OPT(s) cmdOptionExists(argv, argv+argc, s)
#define CMD_GET(s) getCmdOption(argv, argv+argc, s)
//  function instruction:
//  print help infomation
//  self test: aes test, waes test, generate file test, bijction test,
//  aes encode,decode in
//  waes encode, decode in
//  waes generate table save 2 file [whether use external encoding]
using namespace std;


const char* getCmdOption(const char ** begin, const char ** end, const std::string & option)
{
    const char ** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(const char** begin, const char** end, const std::string& option)
{
    return std::find(begin, end, option) != end;
}

void help(){
    printf("usage:\n");
    printf("whiteBoxAes -k <16|24|32 byte key> -e <encrypt file path> -d <decrypt file path> [-l <128|192|256>]\n");
    printf("whiteBoxAes -e <encrypt file path> -s <a string to encrypt> [-l <128|192|256>]\n");
    printf("whiteBoxAes -d <decrypt file path> -s <a string to decrypt> [-l <128|192|256>]\n");
    printf("whiteBoxAes -e <encrypt file path> -f <a file to encrypt> -o <out file>  [-l <128|192|256>]\n");
    printf("whiteBoxAes -d <decrypt file path> -f <a file to decrypt> -o <out file>  [-l <128|192|256>]\n");
    printf("whiteBoxAes -t <bijection|encrypt|decrypt|waes128|file> \n");
    printf("default keylength is 128\n\n");
}


// generate table is slow, you dont like open them all
void test(const std::string& opt){
    if (opt.length() <= 0) {
        return;
    }
    switch (opt.c_str()[0]) {
        case 'b':
            waes_test::test_bijection_generation();
            break;
        case 'e':
            waes_test::test_WAES_128_encrypt();
            break;
        case 'd':
            waes_test::test_WAES_128_encrypt();
            break;
        case 'w':
            waes_test::test_WAES_128();
            break;
        case 'f':
            waes_test::test_WAES_file();
            break;
        default:
            help();
            break;
    }
    //waes_test::test_bijection_generation();
    
    //waes_test::test_AES_128();
    
    //waes_test::test_AES_192();
    
    //waes_test::test_WAES_128();
    
    //waes_test::test_WAES_128_encrypt();
    
    //waes_test::test_WAES_128_decrypt();
    
    //waes_test::test_WAES_128_ex();
    
    //waes_test::test_WAES_file();
}


int generateKeyFile(const std::string & key, const std::string &ef, const std::string &df, keyLength length){

    switch (length) {
        case key128:{
            if (key.size() < length / 8)return 1;
            WAES<key128> waes128((BYTE*)key.c_str());
            waes128.saveKey2File(ef.c_str());
            waes128.saveKey2File(df.c_str(), false);
            break;
        }
        case key192:{
            if (key.size() < length / 8)return 1;
            WAES<key192> waes((BYTE*)key.c_str());
            waes.saveKey2File(ef.c_str());
            waes.saveKey2File(df.c_str(), false);
            break;
        }
        case key256:{
            if (key.size() < length / 8)return 1;
            WAES<key256> waes((BYTE*)key.c_str());
            waes.saveKey2File(ef.c_str());
            waes.saveKey2File(df.c_str(), false);
            break;
        }
        default:
            cout << "unrecognized keylength\n";
            return 1;
            break;
    }
    
    return 0;
}

int encryptString(const std::string &ef, const std::string &str, keyLength length){
    
    int outSize = (int)str.size();
    if (outSize % 16 != 0){
        outSize = outSize + (16 - outSize % 16);
    }
    char * buffer = new char[outSize];
    memset(buffer, 0, outSize);
    switch (length) {
        case key128:{
            
            WAES<key128> waes128(ef.c_str(), true);

            waes128.encrypt(str.c_str(), buffer, str.size());
        
            cout << "cypher\n";
            for (int i=0; i<outSize; i++) {
                printByte(buffer[i]);
            }
            cout << "\n";
            break;
        }
        case key192:{
           
            WAES<key192> waes192(ef.c_str(), true);
            
            waes192.encrypt(str.c_str(), buffer, str.size());
        
            cout << "cypher\n";
            for (int i=0; i<outSize; i++) {
                printByte(buffer[i]);
            }
            cout << "\n";
            break;
        }
        case key256:{
            
            WAES<key256> waes256(ef.c_str(), true);
            
            waes256.encrypt(str.c_str(), buffer, str.size());
            
            cout << "cypher\n";
            for (int i=0; i<outSize; i++) {
                printByte(buffer[i]);
            }
            cout << "\n";
            break;
        }
        default:
            cout << "unrecognized keylength\n";
            return 1;
    }
    return 0;
}

int decryptString(const std::string &ef, const std::string &str, keyLength length){
    
    int outSize = (int)str.size() / 4;
    
    if (outSize % 16 != 0){
        cout << "cypher size should have a factor 16\n";
        return 1;
    }
    
    char * ibuffer = new char[outSize];
    char * obuffer = new char[outSize+1];
    const char* pstr = str.c_str();
    
    memset(obuffer, 0, outSize+1);
    int h,l;
    for (int i=0; i<outSize; i++) {
        
        if( pstr[i * 4 + 2] >= '0' && pstr[i * 4 + 2] <= '9')
            h = (pstr[i * 4 + 2] - '0')* 16;
        else if(pstr[i * 4 + 2] >= 'a' && pstr[i * 4 + 2] <= 'f')
            h = (pstr[i * 4 + 2] - 'a' + 10) * 16;
        else
            h = (pstr[i * 4 + 2] - 'A' + 10) * 16;
        
        if( pstr[i * 4 + 3] >= '0' && pstr[i * 4 + 3] <= '9')
            l = pstr[i * 4 + 3] - '0';
        else if(pstr[i * 4 + 3] >= 'a' && pstr[i * 4 + 3] <= 'f')
            l = pstr[i * 4 + 3] - 'a' + 10;
        else
            l = pstr[i * 4 + 3] - 'A' + 10;
        
        ibuffer[i] = (char)(h + l);
    }
    
    switch (length) {
        case key128:{
            WAES<key128> waes128(ef.c_str(), false);
            waes128.decrypt(ibuffer, obuffer, outSize);
            cout << "cypher\n";
            cout << obuffer << "\n";
            break;
        }
        case key192:{
            
            WAES<key192> waes192(ef.c_str(), false);
            
            waes192.decrypt(ibuffer, obuffer, outSize);
            
            cout << "cypher\n";
            cout << obuffer << "\n";
            break;
        }
        case key256:{
            
            WAES<key256> waes256(ef.c_str(), false);
            
            waes256.decrypt(ibuffer, obuffer, outSize);
        
            cout << "cypher\n";
            cout << obuffer << "\n";
            break;
        }
        default:
            cout << "unrecognized keylength\n";
            delete [] obuffer;
            delete [] ibuffer;
            return 1;
    }
    delete [] obuffer;
    delete [] ibuffer;
    return 0;
}


int encodeFile(const std::string &ef, const std::string &file, const std::string &of, keyLength length, bool isEncrypt){
    switch (length) {
        case key128:{
            
            WAES<key128> waes128(ef.c_str(), isEncrypt);
            if (isEncrypt){
                waes128.encryptFile(file.c_str(), of.c_str());
            }else{
                waes128.decryptFile(file.c_str(), of.c_str());
            }
            break;
        }
        case key192:{
            
            WAES<key192> waes192(ef.c_str(), isEncrypt);
            if (isEncrypt){
                waes192.encryptFile(file.c_str(), of.c_str());
            }else{
                waes192.decryptFile(file.c_str(), of.c_str());
            }
            break;
        }
        case key256:{
            
            WAES<key256> waes256(ef.c_str(), isEncrypt);
            if (isEncrypt){
                waes256.encryptFile(file.c_str(), of.c_str());
            }else{
                waes256.decryptFile(file.c_str(), of.c_str());
            }
            break;
        }
        default:
            cout << "unrecognized keylength\n";
            return 1;
    }
    cout<<"OK\n";
    return 0;
}



int main(int argc, const char * argv[]) {
    
    srand((unsigned)time(NULL));
    
    keyLength length = key128;
    
    if( CMD_OPT("-h")){
        help();
        return 0;
    }
    
    if (CMD_OPT("-t")) {
        test(CMD_GET( "-t"));
        return 0;
    }
    
    if (CMD_OPT("-l")) {
        string opt_l = CMD_GET("-l");
        if (opt_l == "192") {
            length = key192;
        }else if( opt_l == "256"){
            length = key256;
        }
    }
    
    if (CMD_OPT("-e")  && CMD_OPT("-d") && CMD_OPT("-k")) {
        return generateKeyFile(CMD_GET("-k") ,CMD_GET("-e"), CMD_GET("-d"), length);
    }
    
    if (CMD_OPT("-e")  && CMD_OPT("-s")) {
        
        return encryptString(CMD_GET("-e"), CMD_GET("-s"), length);
    }
    
    if (CMD_OPT("-d")  && CMD_OPT("-s")) {
        
        return decryptString(CMD_GET("-d"), CMD_GET("-s"), length);
    }
    
    if (CMD_OPT("-e")  && CMD_OPT("-f") && CMD_OPT("-o")) {
        
        return encodeFile(CMD_GET("-e"), CMD_GET("-f"), CMD_GET("-o"), length, true);
    }
    
    if (CMD_OPT("-d")  && CMD_OPT("-f") && CMD_OPT("-o")) {
        
        return encodeFile(CMD_GET("-d"), CMD_GET("-f"), CMD_GET("-o"), length, false);
    }
    help();
    return 0;
}
