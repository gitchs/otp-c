cmake_minimum_required(VERSION 3.10)
project(otp)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 99)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})


add_library(otp STATIC otp.c)

add_executable(otptest test.cc)
target_link_libraries(otptest ${OPENSSL_LIBRARIES} otp)

