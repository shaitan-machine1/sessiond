//! Typed public D-Bus protocol for sessiond.

pub const BUS_NAME: &str = "org.decoupling.sessiond1";
pub const OBJECT_PATH: &str = "/org/decoupling/sessiond1";
pub const INTERFACE_NAME: &str = "org.decoupling.sessiond1.Manager";

pub type SessionDescription = (String, u32);

#[zbus::proxy(
    interface = "org.decoupling.sessiond1.Manager",
    default_service = "org.decoupling.sessiond1",
    default_path = "/org/decoupling/sessiond1"
)]
pub trait Manager {
    fn open_session(&self, uid: u32) -> zbus::Result<(String, String)>;
    fn close_session(&self, sid: &str) -> zbus::Result<()>;
    fn list_sessions(&self) -> zbus::Result<Vec<SessionDescription>>;

    #[zbus(signal)]
    fn session_new(&self, sid: &str, uid: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn session_removed(&self, sid: &str, uid: u32) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_names_are_stable() {
        assert_eq!(BUS_NAME, "org.decoupling.sessiond1");
        assert_eq!(OBJECT_PATH, "/org/decoupling/sessiond1");
        assert_eq!(INTERFACE_NAME, "org.decoupling.sessiond1.Manager");
    }
}
