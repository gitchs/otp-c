#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "otp.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>



int HOTP(const unsigned char* secret, size_t slen, uint64_t counter, char* output) {
    const static unsigned int mod = 1000000;
    int retval = 0;

    // Most Linux distributions for ARM tend to be little-endian only.
    // The x86 architecture is little-endian. 
    // https://developer.arm.com/documentation/den0013/d/Porting/Endianness#:~:text=Most%20Linux%20distributions%20for%20ARM,can%20also%20handle%20little%2Dendian.

#if defined(__GNUC__) || defined(__clang__)
    counter = __builtin_bswap64(counter);
#else
    do {
        unsigned char* cp = (unsigned char*)&counter;
        unsigned char buffer = 0;

        buffer = *cp; *cp = *(cp+7); *(cp+7) = buffer;
        buffer = *(cp+1); *cp = *(cp+6); *(cp+6) = buffer;
        buffer = *(cp+2); *cp = *(cp+5); *(cp+5) = buffer;
        buffer = *(cp+3); *cp = *(cp+4); *(cp+4) = buffer;
    } while(0);
#endif

    unsigned char digest[20] = {0};
    unsigned int dlen = 0;

    HMAC(EVP_sha1(), secret, slen, (const unsigned char*)&counter, sizeof(counter), digest, &dlen);

    unsigned char offset = digest[19] & 0x0f;
    uint32_t bin_code = digest[offset]&0x7f; bin_code <<= 8;
    bin_code |= digest[offset+1] & 0xff; bin_code <<=8;
    bin_code |= digest[offset+2] & 0xff; bin_code <<=8;
    bin_code |= digest[offset+3] & 0xff;

    sprintf(output, "%06u", bin_code % mod);
    return retval;
}


int TOTP(const unsigned char* secret, size_t slen, time_t t, char* output) {
    // https://en.wikipedia.org/wiki/Time-based_one-time_password
    // TX is the length of one time duration (e.g. 30 seconds).
    const static uint64_t TX = 30;
    uint64_t counter = t / TX;
    return HOTP(secret, slen, counter, output);
}

