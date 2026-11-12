# lib-sessiond

Synchronous session-domain library used by PAM, the daemon, and administrative
clients.

`SessionCore::open_session` is root-only and performs the serialized local PAM
open transaction: create/move/track the session leader, secure the runtime
directory, reuse or start the manager PAM host for UIDs at or above
`user_service_manager.min_uid` (default 1000), await readiness for a new manager,
and attempt `SessionNew` while holding the per-UID lock. Lower UIDs get the same
session/runtime result without inspecting, starting or replacing a manager.
`min_uid = 0` enables managers for every UID. The threshold never suppresses
normal close/last-session cleanup of already-existing resources.

`list_sessions` and `session_for_process` derive state only from containment.
Inventory is lock-free and returns SID/UID plus the recorded leader identity
without a liveness probe. There is no lifecycle database, failed-open journal,
or startup cleanup replay.

The `bus` module provides blocking daemon clients and root lifecycle signal
publication. `CloseSession` and `ScheduleCloseSession` schedule only;
`CloseSessionAndWait` is used by the blocking client.

`daemon_support::execute_close_session` is the sole teardown implementation. It
acquires the UID lock, handles configured target/subtree termination and forced
escalation, confirms drain, removes descendants deepest-first, emits
`SessionRemoved`, and performs applicable manager/runtime/container cleanup.
PAM and CLI callers must request daemon execution rather than call this function.
