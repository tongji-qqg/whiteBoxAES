//
//  bijection.cpp
//  whiteboxAes
//
//  Created by bryce on 15/5/25.
//  Copyright (c) 2015年 qiqingguo. All rights reserved.
//

#include "bijection.h"


/**
 * generate a random non single matrix of rank n
 * recursive part
 * http://www.eecs.berkeley.edu/Pubs/TechRpts/1991/CSD-91-658.pdf
 */
void genMat(NTL::mat_GF2& A,NTL::mat_GF2&T,int n){
    
    NTL::ident(A, n);
    NTL::ident(T, n);
    if (1 >= n) {
        return;
    }
    
    int r = rand() % n;
    
    for (int i=0; i<n; i++) {
        A[0][i] = 0;
        T[r][i] = 0;
    }
    A[0][r] = 1; T[r][r] = 1;
    
    for (int i=r+1; i<n; i++) {
        T[r][i] = rand()%2;
    }
    for (int i=0; i<n; i++) {
        if (i==r)continue;
        T[i][r] = 0;
    }
    
    NTL::mat_GF2 AM,TM;
    genMat(AM, TM, n-1);
    for (int i=1,ii=0; i<n; i++) {
        for (int j=0,jj=0; j<n; j++) {
            if (j == r ) {
                continue;
            }
            A[i][j] = AM[ii][jj++];
        }
        ii++;
    }
    for (int i=0,ii=0; i<n; i++) {
        if (i == r) {
            continue;
        }
        for (int j=0,jj=0; j<n; j++) {
            if (j == r || i == r) {
                continue;
            }
            T[i][j] = TM[ii][jj++];
        }
        ii++;
    }
}

/**
 * generate a random non single matrix of rank n
 * call part
 * http://www.eecs.berkeley.edu/Pubs/TechRpts/1991/CSD-91-658.pdf
 */
NTL::mat_GF2& randomMixingBijection(NTL::mat_GF2 &x, int rank){
    NTL::mat_GF2 A,T;
    A.SetDims(rank, rank);
    T.SetDims(rank, rank);
    
    genMat(A,T,rank);
    NTL::mul(x, A, T);
    return x;
}