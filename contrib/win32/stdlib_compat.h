#ifndef STDLIB_COMPAT_H
#define STDLIB_COMPAT_H

#ifdef _WIN32
#include <stdlib.h>

int setenv(const char *name, const char *value, int overwrite);
void unsetenv(const char *name);
#endif

#endif // STDLIB_COMPAT_H