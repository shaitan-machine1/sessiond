/* Private-stack fixture: arbitrary PAM state must not cross credential exec. */
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
PAM_EXTERN int pam_sm_open_session(pam_handle_t *h,int flags,int argc,const char **argv) {
    (void)h;(void)flags;(void)argc;(void)argv;
    int fd=open("/dev/null",O_RDONLY); if(fd<0) return PAM_SYSTEM_ERR;
    if(dup2(fd,100)<0) { close(fd); return PAM_SYSTEM_ERR; }
    close(fd);
    return setenv("PRIVATE_SECRET","must-not-cross-exec",1)==0 ? PAM_SUCCESS : PAM_SYSTEM_ERR;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *h,int flags,int argc,const char **argv) {
    (void)h;(void)flags;(void)argc;(void)argv; close(100); return PAM_SUCCESS;
}
