/* Disposable foreground manager: verify credential/FD/environment boundaries,
 * advertise actual readiness, leave an ordinary descendant for subtree drain. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
static volatile sig_atomic_t stop;
static void handler(int s) { (void)s; stop=1; }
int main(int argc,char **argv) {
    assert(argc==3 && !strcmp(argv[1],"--ready-fd") && !strcmp(argv[2],"3"));
    assert(geteuid()==TEST_UID && getegid()==TEST_GID);
    assert(!getenv("PRIVATE_SECRET"));
    assert(fcntl(100,F_GETFD)==-1 && errno==EBADF);
    assert(signal(SIGTERM,handler)!=SIG_ERR);
    pid_t descendant=fork(); assert(descendant>=0);
    if (!descendant) { close(3); signal(SIGTERM,SIG_IGN); for (;;) pause(); }
    char *path=NULL; assert(asprintf(&path,"%s/manager-instance",getenv("XDG_RUNTIME_DIR"))>0);
    FILE *file=fopen(path,"w"); assert(file); fprintf(file,"%d %d\n",(int)getpid(),(int)descendant); assert(!fclose(file)); free(path);
    char ready=1; assert(write(3,&ready,1)==1); close(3);
    while (!stop) pause();
    return 0;
}
