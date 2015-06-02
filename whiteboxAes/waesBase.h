#ifndef __WAES_BASE_H__
#define __WAES_BASE_H__

# include "type.h"
# include "util.h"
# include "waesGenerator.h"
# include "WaesFile.h"
# include <fstream>
//
// WAES 声明

template<keyLength L>
class WAES_BASE{
    
protected:
    
    //Nb Number of columns (32-bit words) comprising the State. For this standard = 4.
    static const int m_nSection;
    
    //Nr Number of rounds, which is a function of Nk and Nb (which isfixed). For this standard, Nr = 10, 12, or 14.
    int m_nRounds;
    
    
    //WaesTables<L> *enKeyTable,    *deKeyTable;  // all look up tables
    
    bool          initEnKeyTable, initDeKeyTable;
    
    
    int FILE_BUFFER_SIZE;
    
    void byte2W128b(W128b& in, const BYTE* b, int blockSize = 16);
    
    void baseInit(){
        m_nRounds = L/32+6;
        initDeKeyTable = false;
        initEnKeyTable = false;
        FILE_BUFFER_SIZE = 4096;
    }
    
public:
    
    virtual void cypherBlock(W128b &in, BYTE *out, bool isEncrypt = true) = 0;
    
    WaesFile *wfile;
    
    // here, mentor require separate two table into two differern
    // files, so change into 2 paramater
    int saveKey2File(const char* path, bool isEncrypt = true);
    
    int loadKeyFromFile(const char* path, bool isEncrypt = true);
	
    int encryptBlock(const BYTE *in, BYTE * out, int blockSize = 16);
    
    int decryptBlock(const BYTE *in, BYTE * out, int blockSize = 16);
    
    int encrypt(const char* in, char* out, long length);
    
    int decrypt(const char* in, char* out, long length);
    
    int encryptFile(const char* inPath, const char* outPath);
    
    int decryptFile(const char* inPath, const char* outPath);
    
    NTL::mat_GF2 f,g,fi,gi;
};


template<keyLength L>
const int WAES_BASE<L>::m_nSection = 4;




// make 16byte or less to W128b
template<keyLength L>
void WAES_BASE<L>::byte2W128b(W128b &t, const BYTE *b, int blockSize){
    for (int i=0; i < blockSize; i++) {
        t.B[i] = b[i];
    }
    for (int i=blockSize; i < BLOCK_BYTE_NUM; i++){
        t.B[i] = 0;
    }
}




template<keyLength L>
int WAES_BASE<L>::encryptBlock(const BYTE* in, BYTE *out, int blockSize){
    if (! this->initEnKeyTable) {
        return 1;
    }
    if (blockSize > 16 || blockSize < 0) {
        return 2;
    }
    W128b t;
    byte2W128b(t, in, blockSize);
    cypherBlock(t, out, true);
    return 0;
}




template<keyLength L>
int WAES_BASE<L>::decryptBlock(const BYTE* in, BYTE *out, int blockSize){
    if (! this->initDeKeyTable) {
        return 1;
    }
    if (blockSize > 16 || blockSize < 0) {
        return 2;
    }
    W128b t;
    byte2W128b(t, in, blockSize);
    cypherBlock(t, out, false);
    return 0;
}

template<keyLength L>
int WAES_BASE<L>::encrypt(const char* in, char* out, long length){
    const char* pin = in;
    char* pout = out;
    long remain = length;
    
    while (remain > 0) {
        int size = (remain - 16) > 0 ? 16 : (int)remain;
        int r = encryptBlock((BYTE*)pin, (BYTE*)pout, size);
        if (0 != r) return r;
        pin += size;
        pout += size;
        remain -= size;
    }
    return 0;
}

template<keyLength L>
int WAES_BASE<L>::decrypt(const char* in, char* out, long length){
    const char* pin = in;
    char* pout = out;
    long remain = length;
    
    while (remain > 0) {
        int size = (remain - 16) > 0 ? 16 : (int)remain;
        int r = decryptBlock((BYTE*)pin, (BYTE*)pout, size);
        if (0 != r)return r;
        pin += size;
        pout += size;
        remain -= size;
    }
    return 0;
}

template<keyLength L>
int WAES_BASE<L>::encryptFile(const char *inPath, const char *outPath){
    char  inBuffer[FILE_BUFFER_SIZE], outBuffer[FILE_BUFFER_SIZE];
    
    std::ifstream infile(inPath, std::ios::in);
    
    if (! infile) {
        std::cout << "cannot open file " << inPath << "\n";
        return 1;
    }
    
    std::ofstream outfile(outPath, std::ios::out|std::ios::trunc);
    if (! outfile) {
        std::cout << "cannot open file " << outPath << "\n";
        return 1;
    }
    
    infile.seekg(0, std::ios::end);
    std::streamsize size = infile.tellg();
    infile.seekg(0, std::ios::beg);
    
    long q = size / FILE_BUFFER_SIZE;
    long r = size % FILE_BUFFER_SIZE;
    for (int i=0; i<q; i++) {
        if (infile.read(inBuffer, FILE_BUFFER_SIZE))
        {
            encrypt(inBuffer, outBuffer, FILE_BUFFER_SIZE);
            if ( !outfile.write(outBuffer, FILE_BUFFER_SIZE)) {
                std::cout<< "write file to buffer Error" << "\n";
                return 2;
            }
        }
    }
    memset(inBuffer, 0, sizeof(char)*FILE_BUFFER_SIZE);
    if (infile.read(inBuffer, r))
    {
        int padding = r % 16;
        if (padding != 0) {
            padding = 16 - padding;
        }
        encrypt(inBuffer, outBuffer, r);
        outBuffer[r + padding] = padding;
        
        if ( !outfile.write(outBuffer, r + padding + 1)) {
            std::cout<< "write file to buffer Error" << "\n";
            return 3;
        }
    }
    infile.close();
    outfile.close();
    return 0;
}

template<keyLength L>
int WAES_BASE<L>::decryptFile(const char *inPath, const char *outPath){
    char  inBuffer[FILE_BUFFER_SIZE], outBuffer[FILE_BUFFER_SIZE];
    
    std::ifstream infile(inPath, std::ios::in);
    
    if (! infile) {
        std::cout << "cannot open file " << inPath << "\n";
        return 1;
    }
    
    std::ofstream outfile(outPath, std::ios::out|std::ios::trunc);
    if (! outfile) {
        std::cout << "cannot open file " << outPath << "\n";
        return 1;
    }
    
    infile.seekg(0, std::ios::end);
    std::streamsize size = infile.tellg();
    infile.seekg(0, std::ios::beg);
    
    // last byte is padding size
    long q = (size - 1)/ FILE_BUFFER_SIZE;
    long r = (size - 1) % FILE_BUFFER_SIZE;
    
    for (int i=0; i<q; i++) {
        if (infile.read(inBuffer, FILE_BUFFER_SIZE))
        {
            decrypt(inBuffer, outBuffer, FILE_BUFFER_SIZE);
            if ( !outfile.write(outBuffer, FILE_BUFFER_SIZE)) {
                std::cout<< "write file to buffer Error" << "\n";
                return 2;
            }
        }
    }
    if (infile.read(inBuffer, r))
    {
        char padding;
        infile.read(&padding, 1);
        
        decrypt(inBuffer, outBuffer, r);
        if ( !outfile.write(outBuffer, r - padding)) {
            std::cout<< "write file to buffer Error" << "\n";
            return 3;
        }
    }
    infile.close();
    outfile.close();
    return 0;
}
#endif
