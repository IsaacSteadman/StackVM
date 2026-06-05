#ifndef STRING_H
#define STRING_H

#include "stackvm.h"

void *memcpy(void *dest, const void *src, size_t num);
void *memmove(void *dest, void *src, size_t num);
void *memset(void *ptr, unsigned char value, size_t num);
int memcmp(const void *ptr1, const void *ptr2, size_t num);

size_t strlen(const char *str);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t num);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t num);

#endif /* STRING_H */
