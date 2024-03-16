// xor.c

#include "xor.h"
#include <stddef.h>
#include <string.h>


// ��̬�������洢��Կ
static const char* static_key = "default_key";
// �����ܺ���ʵ��
void xorEncrypt(unsigned char* buffer, size_t size) {
    size_t keyLen = strlen(static_key);
    for (size_t i = 0; i < size; ++i) {
        buffer[i] ^= static_key[i % keyLen]; // ѭ��������Կ
    }
}
