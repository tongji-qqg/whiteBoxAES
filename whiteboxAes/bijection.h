//
//  bijection.h
//  whiteboxAes
//
//  Created by bryce on 15/5/25.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#ifndef __whiteboxAes__bijection__
#define __whiteboxAes__bijection__

#include <stdio.h>
#include <time.h>
#include <iostream>
#include <unistd.h>
#include <NTL/mat_GF2.h>

NTL::mat_GF2& randomMixingBijection(NTL::mat_GF2 &x, int rank);
template<typename T> int generateRandomBijectionT(T * bijection, T * inverse, int size, int init);

#endif /* defined(__whiteboxAes__bijection__) */
