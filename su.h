#ifndef SU_H
#define SU_H

#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <shadow.h>
#include <termios.h>
#include <unistd.h>
#include <crypt.h>

#define PWD_MAX 128
#define SHELL "/bin/bash"
#define USER_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin:/usr/lib/llvm/16/bin:/usr/lib/llvm/15/bin"
#define ROOT_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin:/usr/lib/llvm/16/bin:/usr/lib/llvm/15/bin"

#endif

