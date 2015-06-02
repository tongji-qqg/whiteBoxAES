//
//  test.cpp
//  whiteboxAes
//
//  Created by bryce on 15/5/30.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#include <assert.h>
#include "test.h"
#include "aes.h"
#include "waes.h"
#include "waesExpandXor.h"
#include "waesGenerator.h"
#include "bijection.h"

/////////// 128
namespace waes_test {
    
    const BYTE key[]  = {
        0x2b,0x7e,0x15,0x16,
        0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,
        0x09,0xcf,0x4f,0x3c};
    
    
    const BYTE input[] =  {
        0x32,0x43,0xf6,0xa8,
        0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,
        0xe0,0x37,0x07,0x34};
    
    
    const BYTE output[] = {
        0x39, 0x25, 0x84, 0x1D,
        0x02, 0xDC, 0x09, 0xFB,
        0xDC, 0x11, 0x85, 0x97,
        0x19, 0x6A, 0x0B, 0x32};
    
    
    ///////////// 128
    BYTE key2[] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f};
    
    BYTE input2[] = {
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,
        0xcc,0xdd,0xee,0xff
    };
    
    BYTE output2[] = {
        0x69,0xc4,0xe0,0xd8,
        0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,
        0x70,0xb4,0xc5,0x5a
    };
    
    //////////// 192
    BYTE key3[] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,
        0x14,0x15,0x16,0x17};
    
    BYTE input3[] = {
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,
        0xcc,0xdd,0xee,0xff
    };
    
    BYTE output3[] = {
        0xdd,0xa9,0x7c,0xa4,
        0x86,0x4c,0xdf,0xe0,
        0x6e,0xaf,0x70,0xa0,
        0xec,0x0d,0x71,0x91
    };

    int test_bijection_generation(){
        std::cout << "test bijection generation... \n";
        NTL::mat_GF2 bij;
        for(int i=0;i<10;i++){
            randomMixingBijection(bij, 128);
            NTL::GF2 det = NTL::determinant(bij);
            assert(det == 1);
        }
        for(int i=0;i<10;i++){
            randomMixingBijection(bij, 8);
            NTL::GF2 det = NTL::determinant(bij);
            assert(det == 1);
        }
        for(int i=0;i<10;i++){
            randomMixingBijection(bij, 4);
            NTL::GF2 det = NTL::determinant(bij);
            assert(det == 1);
        }
        std::cout << "test random mixing bijection OK" << "\n";
        return 0;
    }
    

    int test_AES_128(){
        
        std::cout << "test AES 128 correctness\n";
        
        AES<key128> aes(key);
        BYTE res[16];
        aes.encryptBlock(input, res);
        assert(compareBlock(res, output) == true);
        
        aes.decryptBlock(output, res);
        assert(compareBlock(res, input) == true);
        
        AES<key128> aes2(key2);

        aes2.encryptBlock(input2, res);
        assert(compareBlock(res, output2) == true);
        
        aes2.decryptBlock(output2, res);
        assert(compareBlock(res, input2) == true);
        
        std::cout << "AES 128 block cypher is OK\n";
        return 0;
    }
    
    int test_AES_192(){
        
        std::cout << "test AES 192 correctness\n";
        
        AES<key192> aes192(key3);
        BYTE res[16];
        
        aes192.encryptBlock(input3, res);
        assert(compareBlock(res, output3));
        
        aes192.decryptBlock(output3, res);
        assert(compareBlock(res, input3));
        
        std::cout << "AES 192  block cypher is OK\n";
        return 0;
    }
    
    int test_WAES_128_encrypt(){
        
        std::cout << "test WAES 128 encrypt correctness\n";
        // ---------------------         -----------
        // | f * waes.en() * g | * g-1  *| aes.de()|  * f-1
        // ---------------------         -----------
        WAES<key128> waes(key);
        AES<key128> aes(key);
        BYTE res[16], res2[16];
        
        waes.encryptBlock(input, res);
        
        matMulByte(res2, waes.gi, res, 128);
        aes.decryptBlock(res2, res);
        matMulByte(res2, waes.fi, res, 128);
        
        assert(compareBlock(res2, input));
        
        std::cout << "WAES 128  encrypt cypher is OK\n";
        return 0;
    }
    
    int test_WAES_128_decrypt(){
        
        std::cout << "test WAES 128 decrypt correctness\n";
        //      ------------     ----------------------------
        //  f * | aes.en() | * g | * g-1  * waes.de()  * f-1 |
        //      ------------     ----------------------------
        WAES<key128> waes(key);
        AES<key128> aes(key);
        BYTE res[16], res2[16];
        
        matMulByte(res, waes.f, input, 128);
        aes.encryptBlock(res, res2);
        matMulByte(res, waes.g, res2, 128);
        
        waes.decryptBlock(res, res2);
        
        assert(compareBlock(res2, input));
        
        std::cout << "WAES 128  decrypt cypher is OK\n";
        return 0;
    }
    
    int test_WAES_128(){
        
        std::cout << "test WAES 128 with cancellation external encoding correctness\n";
        // ---------------------   --------------------------
        // | f * waes.en() * g | * |g-1  * waes.de()  * f-1 |
        // ---------------------   --------------------------
        WAES<key128> waes(key);
        BYTE res[16], res2[16];
        
        waes.encryptBlock(input, res);
        waes.decryptBlock(res, res2);
        assert( compareBlock(res2, input) == true);
        
        std::cout << "WAES 128 block cypher is OK\n";
        return 0;
    }
    
    
    int test_WAES_128_ex(){
        
        std::cout << "test WAES 128 with external encoding correctness\n";
        //     ---------------------   --------------------------
        // f * | f-1 * waes.en() * g | * |g-1  * waes.de()  * h |  * h-1
        //     ---------------------   --------------------------
        
        BYTE res[16], res2[16];
        NTL::mat_GF2 h, hi, f, fi, g, gi;
        randomMixingBijection(h, 128);
        randomMixingBijection(f, 128);
        randomMixingBijection(g, 128);
        NTL::inv(hi,h);NTL::inv(fi,f);NTL::inv(gi,g);
        
        WAES<key128> waes_en(key, fi, g);
        WAES<key128> waes_de(key, hi, g);
        
        matMulByte(res, f, input, 128);
        waes_en.encryptBlock(res, res2);
        waes_de.decryptBlock(res2, res);
        matMulByte(res2, hi, res, 128);
        
        
        assert( compareBlock(res2, input) == true);
        
        std::cout << "WAES 128 external encoding block cypher is OK\n";
        return 0;
    }
    
    int test_WAES_file(){
        
        std::cout << "test WAES 128 lookup table file correctness\n";
        
        BYTE res[16], res2[16];
        //WAES<key128> waes(key);
        //waes.saveKey2File("./wkey128_test.en", true);
        //waes.saveKey2File("./wkey128_test.de", false);
        WAES<key128> wwaes("./wkey128_test.en", "./wkey128_test.de");
        
        wwaes.encryptBlock(input, res);
        wwaes.decryptBlock(res, res2);
        
        assert(compareBlock(res2, input) == true);
        std::cout << "test WAES 128 lookup table file OK\n";
        return 0;
    }
    
    void compare_time_shrank_xor(){
        
        clock_t t;
        BYTE aesEnOut[16], aesDeOut[16];
        BYTE waesEnOut[16], waesDeOut[16];
        BYTE waessxEnOut[16], waessxDeOut[16];
        
        
        AES<key128> aes(key);
        t = clock();
        aes.encryptBlock(input, aesEnOut);
        aes.decryptBlock(aesEnOut, aesDeOut);
        t = clock() - t;
        printf ("AES %ld clicks (%f seconds).\n",t,((float)t)/CLOCKS_PER_SEC);
        
        
        //WAES<L> waes(key);
        WAES<key128> waes("/Users/bryce/wkey128.sx.en","/Users/bryce/wkey128.sx.de");
        t = clock();
        waes.encryptBlock(input,waesEnOut);
        waes.decryptBlock(waesEnOut, waesDeOut);
        t = clock() - t;
        printf ("WAES %ld clicks (%f seconds).\n",t,((float)t)/CLOCKS_PER_SEC);
        
        //compareBlock(aesDeOut, waesDeOut);
        
        //WAESSX<L>waessx(key);
        WAESEX<key128>waesex("/Users/bryce/wkey128.en","/Users/bryce/wkey128.de");
        t = clock();
        waesex.encryptBlock(input,waessxEnOut);
        waesex.decryptBlock(waessxEnOut, waessxDeOut);
        t = clock() - t;
        printf ("WAES Expand Block %ld clicks (%f seconds).\n",t,((float)t)/CLOCKS_PER_SEC);
        
        //compareBlock(aesDeOut, waessxDeOut);
    }
}