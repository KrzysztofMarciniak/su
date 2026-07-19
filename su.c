#include "su.h"

static void write_error(const char *msg)
{
    write(STDERR_FILENO, msg, strlen(msg));
}

static void switch_user(struct passwd *user, char **program, char change_environment)
{
    if (setgid(user->pw_gid) < 0 || setuid(user->pw_uid) < 0) {
        write_error("setgid/setuid failed\n");
        exit(EXIT_FAILURE);
    }
    
    char const *term = getenv("TERM");
    if (term) setenv("TERM", term, change_environment);
    
    setenv("HOME", user->pw_dir, change_environment);
    setenv("SHELL", user->pw_shell, change_environment);
    setenv("USER", user->pw_name, change_environment);
    setenv("LOGNAME", user->pw_name, change_environment);
    setenv("PATH", user->pw_uid ? USER_PATH : ROOT_PATH, change_environment);

    if (!program) {
        execl(user->pw_shell ?: SHELL, user->pw_shell ?: SHELL, (char*)NULL);
        write_error("execl failed\n");
        exit(EXIT_FAILURE);
    }
    
    if (execvp(*program, program) == -1) {
        write(STDERR_FILENO, *program, strlen(*program));
        write_error(": command not found\n");
        exit(EXIT_FAILURE);
    }
}

static void erase_from_memory(void *s, size_t n)
{
    volatile unsigned char *p = s;
    while(n--) *p++ = 0;
}

static int check_password(struct spwd* shadow)
{
    if (!shadow->sp_pwdp || !*shadow->sp_pwdp || !strcmp(shadow->sp_pwdp, "*")) {
        write_error("Empty password not allowed\n");
        exit(EXIT_FAILURE);
    }
    
    char pass[PWD_MAX + 1];
    struct termios old_term, new_term;
    
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    
    write(STDOUT_FILENO, "Password: ", 10);
    
    int n = read(STDIN_FILENO, pass, PWD_MAX);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    
    if (n <= 0) {
        erase_from_memory(pass, sizeof(pass));
        write_error("read failed\n");
        exit(EXIT_FAILURE);
    }
    
    pass[n - 1] = '\0';
    char *hashed = crypt(pass, shadow->sp_pwdp);
    erase_from_memory(pass, sizeof(pass));
    
    if (!hashed || strcmp(hashed, shadow->sp_pwdp)) {
        write_error("Authentication failed\n");
        exit(EXIT_FAILURE);
    }
    
    return 0;
}

int main(int argc, char **argv)
{
    uid_t ruid = getuid();
    struct passwd *user = NULL;
    char **program = NULL;
    char change_environment = 1;
    
    if (argc == 1) {
        user = getpwuid(0);
    } else {
        char **ptr = argv + 1;
        while (*ptr) {
            if (!strcmp(*ptr, "-c") && ptr[1]) {
                program = ptr + 1;
                *ptr = NULL;
                ptr++;
            } else if (!strcmp(*ptr, "-m") || !strcmp(*ptr, "-p")) {
                change_environment = 0;
                ptr++;
            } else if (!user) {
                user = getpwnam(*ptr);
                ptr++;
            } else {
                ptr++;
            }
        }
        if (!user) user = getpwuid(0);
    }
    
    if (!user) {
        write_error("User does not exist\n");
        return EXIT_FAILURE;
    }
    
    if (ruid && ruid != user->pw_uid) {
        struct spwd* shadow = getspnam(user->pw_name);
        if (!shadow) {
            write_error("Cannot access shadow entry\n");
            return EXIT_FAILURE;
        }
        check_password(shadow);
    }
    
    switch_user(user, program, change_environment);
    return EXIT_FAILURE;
}

