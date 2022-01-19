#include <iostream>
#include <cstring>
#include <cassert>
#include <time.h>
#include "openssl/ssl.h"
#include "otp.h"

struct TestCase {
    uint64_t counter;
    char code[16];
};


int main(int argc, char** args) {
    SSL_library_init(); // YOU SHOULD INIT SSL YOURSELF

    const unsigned char secret[] = {105, 116, 32, 119, 111, 114, 107, 115};
    uint32_t counter = 0;
    char output[32] = {0};

    struct TestCase cases[] = {
        {0, "589511"},
        {1, "577914"},
        {2, "161463"},
        {3, "679608"},
        {4, "798396"},
        {5, "296513"},
        {6, "960531"},
        {7, "015650"},
        {8, "706124"},
        {9, "632316"},
        {10, "084253"},
        {11, "365671"},
        {12, "208259"},
        {13, "928972"},
        {14, "578454"},
        {15, "273403"},
        {16, "064499"},
        {17, "373756"},
        {18, "732496"},
        {19, "200182"},
        {20, "601882"},
        {21, "622765"},
        {22, "068158"},
        {23, "398765"},
        {24, "468796"},
        {25, "151151"},
        {26, "543124"},
        {27, "483908"},
        {28, "823855"},
        {29, "179797"},
        {30, "972202"},
        {31, "100346"}
    };


    for (uint32_t counter=0; counter < 32; counter++) {
        HOTP(secret, sizeof(secret), counter, output);
        assert(std::strcmp(output, cases[counter].code) == 0);
    }
	std::cout << "ALL TEST CASES PASSED." <<std::endl;

    return 0;
}
