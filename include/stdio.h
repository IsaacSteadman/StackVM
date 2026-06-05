#ifndef STDIO_H
#define STDIO_H

#include "stackvm.h"
#include "stdarg.h"

int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

#endif /* STDIO_H */
