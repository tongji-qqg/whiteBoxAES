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

namespace waes_test {
    
    int test_AES_128();
    int test_AES_192();
    
    int test_WAES_128_encrypt();
    int test_WAES_128_decrypt();
    
    int test_WAES_128();
    int test_WAES_128_ex();

    int test_WAES_file();
    
    int test_bijection_generation();
}


#endif /* defined(__whiteboxAes__test__) */
