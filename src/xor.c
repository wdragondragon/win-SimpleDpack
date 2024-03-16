// xor.c

#include "xor.h"
#include <stddef.h>
#include <string.h>


// 静态变量，存储密钥
static const char* static_key = "default_key";
// 异或加密函数实现
void xorEncrypt(unsigned char* buffer, size_t size) {
    size_t keyLen = strlen(static_key);
    for (size_t i = 0; i < size; ++i) {
        buffer[i] ^= static_key[i % keyLen]; // 循环利用密钥
    }
}
