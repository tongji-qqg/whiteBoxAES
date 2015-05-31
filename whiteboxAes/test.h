//
//  test.h
//  whiteboxAes
//
//  Created by bryce on 15/5/30.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#ifndef __whiteboxAes__test__
#define __whiteboxAes__test__

#include <stdio.h>

int test_AES_encrypt_block();
int test_AES_decrypt_block();
int test_AES_encrypt_ECB();
int test_AES_encrypt_CBC();
int test_AES_decrypt_ECB();
int test_AES_decrypt_CBC();

int test_WAES_encrypt_block();
int test_WAES_decrypt_block();
int test_WAES_encrypt_ECB();
int test_WAES_encrypt_EBC();
int test_WAES_decrypt_ECB();
int test_WAES_decrypt_CBC();

int test_bijection_generation();

int test_WaesGenerator_writeFile();

int test_WaesGenerator_readFile();

#endif /* defined(__whiteboxAes__test__) */
