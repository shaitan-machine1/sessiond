/* Explicit disposable cgroup only. Interactive host for root-e2e.py. */
#define _GNU_SOURCE
#include <sessiond.h>
#include <security/pam_appl.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static int conversation(int n, const struct pam_message **m, struct pam_response **r, void *d) { (void)n;(void)m;(void)d;*r=NULL;return PAM_CONV_ERR; }
static void checked(uint32_t code, sessiond_error **error) {
    if (code) { fprintf(stderr,"SDK %u: %s\n",code,*error ? (*error)->message : "missing error"); exit(1); }
    assert(!*error);
}
int main(int argc, char **argv) {
    if (argc < 5) return 64;
    if (!strcmp(argv[1],"exec")) {
        char *path=NULL; assert(asprintf(&path,"%s/cgroup.procs",argv[2])>0);
        FILE *file=fopen(path,"w"); assert(file); assert(fprintf(file,"%u\n",(unsigned)getpid())>0); assert(!fclose(file)); free(path);
        execv(argv[3],&argv[3]); return 127;
    }
    setvbuf(stdout,NULL,_IOLBF,0);
    sessiond_session *opened=NULL; sessiond_error *error=NULL; pam_handle_t *pam=NULL;
    const char *root=argv[2]; uint32_t uid=(uint32_t)strtoul(argv[3],NULL,10);
    if (!strcmp(argv[1],"local")) checked(sessiond_open_session(uid,root,&opened,&error),&error);
    else if (!strcmp(argv[1],"pam") && argc == 8) {
        struct pam_conv conv={conversation,NULL};
        int s=pam_start_confdir(argv[5],argv[4],&conv,argv[6],&pam); assert(s==PAM_SUCCESS);
        assert(pam_putenv(pam,"XDG_SESSION_ID=stale")==PAM_SUCCESS);
        assert(pam_putenv(pam,"XDG_RUNTIME_DIR=/stale")==PAM_SUCCESS);
        assert(pam_putenv(pam,"XDG_SEAT=supplied-unverified-seat")==PAM_SUCCESS);
        s=pam_open_session(pam,0);
        if (s!=PAM_SUCCESS) { printf("PAMERROR %d\n",s); pam_end(pam,s); return 2; }
        const char *sid=pam_getenv(pam,"XDG_SESSION_ID"), *runtime=pam_getenv(pam,"XDG_RUNTIME_DIR");
        assert(sid && strlen(sid)==32 && strcmp(sid,"stale"));
        if (!strcmp(argv[7],"none")) assert(!runtime);
        else assert(runtime && !strcmp(runtime,argv[7]));
        opened=calloc(1,sizeof(*opened)); assert(opened); opened->sid=strdup(sid); opened->uid=uid;
        if (runtime) opened->runtime_dir=strdup(runtime);
    } else return 64;
    uint64_t start=0; checked(sessiond_current_process_start_time(&start,&error),&error);
    printf("OPEN %s %u %u %llu %s\n",opened->sid,opened->uid,(unsigned)getpid(),(unsigned long long)start,opened->runtime_dir ? opened->runtime_dir : "-");
    char *line=NULL; size_t capacity=0;
    while (getline(&line,&capacity,stdin)>0) {
        line[strcspn(line,"\n")]=0;
        if (!strcmp(line,"quit")) break;
        if (!strcmp(line,"duplicate")) {
            sessiond_session *other=(void*)1;
            assert(sessiond_open_session(uid+1,root,&other,&error)==SESSIOND_ALREADY_IN_SESSION && !other);
            sessiond_error_free(error); error=NULL; puts("DUPLICATE"); continue;
        }
        if (!strcmp(line,"nested")) {
            char *path=NULL; assert(asprintf(&path,"%s/sessiond/user/%u/session/%s/arbitrary",root,uid,opened->sid)>0);
            assert(mkdir(path,0755)==0); char *procs=NULL; assert(asprintf(&procs,"%s/cgroup.procs",path)>0);
            FILE *file=fopen(procs,"w"); assert(file); assert(fprintf(file,"%u\n",(unsigned)getpid())>0); assert(!fclose(file)); free(path); free(procs); puts("NESTED"); continue;
        }
        sessiond_client *client=NULL;
        uint32_t code=sessiond_client_new(NULL,5000,&client,&error);
        sessiond_session *info=NULL;
        if (!code && !strcmp(line,"ready")) code=sessiond_ensure_session_ready(client,&info,&error);
        else if (!code && !strcmp(line,"lookup")) code=sessiond_get_session_by_pid(client,(uint32_t)getpid(),start,&info,&error);
        else if (!code && !strcmp(line,"self-close")) code=sessiond_close_session(client,opened->sid,&error);
        else if (!code && !strcmp(line,"attrs")) {
            sessiond_attribute set[]={{"XDG_SEAT","supplied-unverified-seat"},{"runtime_dir","/inert"},{"sid","not-identity"}};
            code=sessiond_update_session_attrs(client,opened->sid,set,3,NULL,0,&error);
            if (!code) code=sessiond_get_session(client,opened->sid,&info,&error);
        }
        if (code) { printf("ERROR %u %s\n",code,error && error->remote_name ? error->remote_name : "local"); sessiond_error_free(error); error=NULL; }
        else if (info) { assert(!strcmp(info->sid,opened->sid) && info->uid==uid); printf("INFO %s %u %s\n",info->sid,info->uid,info->runtime_dir); sessiond_session_free(info); }
        else puts("OK");
        sessiond_client_free(client);
    }
    free(line); sessiond_session_free(opened);
    if (pam) { int s=pam_close_session(pam,0); pam_end(pam,s); printf("CLOSED %d\n",s); return s==PAM_SUCCESS ? 0 : 3; }
    return 0;
}
