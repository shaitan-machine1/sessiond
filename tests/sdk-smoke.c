/* Run against an explicitly staged SDK, optionally an explicit private bus. */
#include <sessiond.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static void ok(uint32_t code, sessiond_error **error) {
    if (code) fprintf(stderr, "sessiond error %u: %s [%s]\n", code, *error ? (*error)->message : "no diagnostic", *error && (*error)->remote_name ? (*error)->remote_name : "local");
    assert(code == 0 && *error == NULL);
}
int main(int argc, char **argv) {
    sessiond_error *error = NULL;
    uint64_t start = 0;
    ok(sessiond_current_process_start_time(&start, &error), &error);
    assert(start > 0);
    sessiond_sessions *rows = (void *)1;
    assert(sessiond_list_sessions(NULL, &rows, &error) == SESSIOND_INVALID_ARGUMENT);
    assert(rows == NULL && error && error->code == SESSIOND_INVALID_ARGUMENT);
    sessiond_error_free(error); error = NULL;
    sessiond_client *client = (void *)1;
    assert(sessiond_client_new(NULL, 0, &client, &error) == SESSIOND_INVALID_ARGUMENT);
    assert(client == NULL && error); sessiond_error_free(error); error = NULL;
    sessiond_session *session = (void *)1;
    /* Never try a valid local open on a host's default containment root. */
    assert(sessiond_open_session(0, "relative", &session, &error) != 0);
    assert(session == NULL && error); sessiond_error_free(error); error = NULL;
    if (argc > 1) {
        ok(sessiond_client_new(argv[1], 2000, &client, &error), &error);
        ok(sessiond_subscribe(client, &error), &error);
        ok(sessiond_list_sessions(client, &rows, &error), &error);
        if (argc > 2) {
            assert(rows->length == 0); /* Partial fixture roots are private. */
            assert(sessiond_get_session(client, argv[2], &session, &error) == SESSIOND_SESSION_NOT_FOUND);
            assert(session == NULL); sessiond_error_free(error); error = NULL;
            uint32_t pid = 0; uint64_t master_start = 0;
            assert(sessiond_get_session_master_pid(client, argv[2], &pid, &master_start, &error) == SESSIOND_SESSION_NOT_FOUND);
            sessiond_error_free(error); error = NULL;
            sessiond_attributes *attrs = NULL;
            assert(sessiond_get_session_attrs(client, argv[2], &attrs, &error) == SESSIOND_SESSION_NOT_FOUND);
            assert(attrs == NULL); sessiond_error_free(error); error = NULL;
            sessiond_attribute set[] = {{"ready", "1"}};
            assert(sessiond_update_session_attrs(client, argv[2], set, 1, NULL, 0, &error) == SESSIOND_INVALID_ARGUMENT);
            sessiond_error_free(error); error = NULL;
        } else assert(rows->length == 0);
        sessiond_sessions_free(rows);
        assert(sessiond_get_session_by_pid(client, (uint32_t)getpid(), start + 1, &session, &error) == SESSIOND_PROCESS_CHANGED);
        assert(session == NULL); sessiond_error_free(error); error = NULL;
        assert(sessiond_get_session_by_pid(client, (uint32_t)getpid(), start, &session, &error) == SESSIOND_NO_SESSION);
        sessiond_error_free(error); error = NULL;
        /* Credential ProcessFD is required; no session is ever allocated here. */
        uint32_t code = sessiond_ensure_session_ready(client, &session, &error);
        assert(code == SESSIOND_NO_SESSION || code == SESSIOND_READINESS_FAILED);
        sessiond_error_free(error); error = NULL;
        const char *absent = "f123456789abcdef0123456789abcdef";
        code = sessiond_schedule_close_session(client, &error);
        assert(code == SESSIOND_NO_SESSION || code == SESSIOND_READINESS_FAILED);
        sessiond_error_free(error); error = NULL;
        code = sessiond_close_session(client, absent, &error);
        assert(code == 0 || code == SESSIOND_READINESS_FAILED);
        if (code) { sessiond_error_free(error); error = NULL; }
        sessiond_event *event = NULL;
        ok(sessiond_next_event(client, 0, &event, &error), &error);
        assert(event == NULL); /* local inventory/startup/attributes emit no hints */
        sessiond_client_free(client);
    }
    sessiond_client_free(NULL); sessiond_error_free(NULL); sessiond_session_free(NULL);
    sessiond_sessions_free(NULL); sessiond_attributes_free(NULL); sessiond_event_free(NULL);
    puts("staged C SDK smoke passed"); return 0;
}
