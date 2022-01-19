#ifndef __HS_OTP_H__
#define __HS_OTP_H__

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

int HOTP(const unsigned char* secret, size_t slen, uint64_t counter, char* output);
int TOTP(const unsigned char* secret, size_t slen, time_t t, char* output);

#ifdef __cplusplus
}
#endif


#endif // __HS_OTP_H__
