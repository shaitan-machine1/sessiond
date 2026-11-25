#ifndef SGLOGIN_SESSIOND_H
#define SGLOGIN_SESSIOND_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* ABI 0: libsessiond.so.0. All strings are UTF-8, NUL-terminated.
 * Inputs are borrowed for the call. Non-NULL pointers must address valid,
 * non-overlapping storage. Clients/results must come from this library and
 * each owned result must be freed exactly once with its matching free function.
 * Never free individual result fields or array elements.
 * Calls return zero on success or an error code below. A supplied error output
 * is set to NULL on success or to an owned error on failure. Pointer-result
 * outputs are NULL on failure; scalar outputs are unspecified on failure.
 * Calls on one client require external serialization. Clients belong to their
 * creating process: never inherit/use them across fork. No runtime/thread is
 * started. Unexpected internal panics terminate the host; ordinary errors do not.
 */
typedef struct sessiond_client sessiond_client;
typedef struct { uint32_t code; char *message; char *remote_name; } sessiond_error;
typedef struct { char *sid; uint32_t uid; char *runtime_dir; } sessiond_session;
typedef struct { sessiond_session *items; size_t length; } sessiond_sessions;
typedef struct { char *name; char *value; } sessiond_attribute;
typedef struct { sessiond_attribute *items; size_t length; } sessiond_attributes;
typedef struct { uint32_t kind; char *sid; uint32_t uid; } sessiond_event;
enum sessiond_error_code {
  SESSIOND_INVALID_ARGUMENT = 1, SESSIOND_NOT_AUTHORIZED, SESSIOND_SESSION_NOT_FOUND,
  SESSIOND_NO_SESSION, SESSIOND_PROCESS_NOT_FOUND, SESSIOND_PROCESS_CHANGED,
  SESSIOND_MASTER_NOT_RECORDED, SESSIOND_ALREADY_IN_SESSION, SESSIOND_BUSY,
  SESSIOND_LIMIT_EXCEEDED, SESSIOND_NOT_READY, SESSIOND_STOPPING,
  SESSIOND_READINESS_FAILED, SESSIOND_CLEANUP_FAILED, SESSIOND_PENDING,
  SESSIOND_BACKEND_ERROR, SESSIOND_TRANSPORT, SESSIOND_UNKNOWN_REMOTE
};
enum sessiond_event_kind { SESSIOND_SESSION_NEW = 1, SESSIOND_SESSION_REMOVED,
  SESSIOND_OWNER_REPLACED, SESSIOND_EVENT_OVERFLOW };

/* NULL address selects the system bus. Explicit addresses support private buses.
 * timeout_ms must be in (0, 3600000]. The unique sessiond owner is verified root.
 */
uint32_t sessiond_client_new(const char *address, uint64_t timeout_ms,
                            sessiond_client **result, sessiond_error **error);
void sessiond_client_free(sessiond_client *);
/* Root-only local self-migration; no bus call, readiness or lifecycle lock.
 * NULL root selects /sys/fs/cgroup. Unsupported: simultaneous open calls in one
 * process. Use a separate PAM host for each independent session. runtime_dir in
 * the returned local result is NULL. A partial failure may leave containment.
 */
uint32_t sessiond_open_session(uint32_t uid, const char *root,
                              sessiond_session **result, sessiond_error **error);
uint32_t sessiond_current_process_start_time(uint64_t *result, sessiond_error **error);
uint32_t sessiond_list_sessions(sessiond_client *, sessiond_sessions **, sessiond_error **);
uint32_t sessiond_get_session(sessiond_client *, const char *sid, sessiond_session **, sessiond_error **);
uint32_t sessiond_get_session_by_pid(sessiond_client *, uint32_t pid, uint64_t start_time, sessiond_session **, sessiond_error **);
uint32_t sessiond_get_session_master_pid(sessiond_client *, const char *sid, uint32_t *pid, uint64_t *start_time, sessiond_error **);
uint32_t sessiond_get_session_attrs(sessiond_client *, const char *sid, sessiond_attributes **, sessiond_error **);
uint32_t sessiond_ensure_session_ready(sessiond_client *, sessiond_session **, sessiond_error **);
uint32_t sessiond_update_session_attrs(sessiond_client *, const char *sid,
    const sessiond_attribute *set, size_t set_length,
    const char *const *remove, size_t remove_length, sessiond_error **);
/* Resolve the authenticated caller's enclosing session, including unready scopes. */
uint32_t sessiond_schedule_close_session(sessiond_client *, sessiond_error **);
/* Success certifies session-tree removal only, not shared-resource cleanup.
 * Pending/timeout is not success; admitted cleanup continues.
 */
uint32_t sessiond_close_session(sessiond_client *, const char *sid, sessiond_error **);
uint32_t sessiond_subscribe(sessiond_client *, sessiond_error **);
/* Explicitly pumps the transport. NULL event on success means no event yet.
 * Owner replacement or overflow invalidates cached inventory/subscriptions.
 * Any invalidation requires a new client, subscribe, then fresh inventory.
 * Further method calls on an invalidated client fail rather than follow owners.
 */
uint32_t sessiond_next_event(sessiond_client *, uint64_t wait_ms, sessiond_event **, sessiond_error **);
/* Borrowed descriptor; timeout_ms=-1 means no transport timer. */
typedef struct { int32_t fd; int16_t events; uint32_t buffered; int64_t timeout_ms; } sessiond_poll_info;
uint32_t sessiond_poll_state(sessiond_client *, sessiond_poll_info *, sessiond_error **);
/* limit=1..256; more=1 means buffered work may remain. Drain next_event too. */
uint32_t sessiond_dispatch(sessiond_client *, uint32_t limit, uint32_t *more, sessiond_error **);
void sessiond_error_free(sessiond_error *);
void sessiond_session_free(sessiond_session *);
void sessiond_sessions_free(sessiond_sessions *);
void sessiond_attributes_free(sessiond_attributes *);
void sessiond_event_free(sessiond_event *);
#ifdef __cplusplus
}
#endif
#endif
