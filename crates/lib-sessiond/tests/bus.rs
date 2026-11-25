#![cfg(feature = "blocking-client")]
use dbus::{blocking::Connection, channel::Sender};
use lib_sessiond::{
    ErrorCode,
    bus::{BUS_NAME, Bus, Client, Event, INTERFACE_NAME, OBJECT_PATH},
};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct PrivateBus(Child);
impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn connect(address: &str) -> Connection {
    let mut channel = dbus::channel::Channel::open_private(address).unwrap();
    channel.register().unwrap();
    Connection::from(channel)
}
fn signal(connection: &Connection, member: &str) {
    let message = dbus::Message::new_signal(OBJECT_PATH, INTERFACE_NAME, member)
        .unwrap()
        .append2("0123456789abcdef0123456789abcdef", 1000u32);
    connection.send(message).unwrap();
    connection.channel().flush();
}
fn event(client: &Client) -> Event {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(event) = client.next_event(Duration::from_millis(10)).unwrap() {
            return event;
        }
        assert!(Instant::now() < deadline, "missing lifecycle hint");
    }
}
#[test]
fn root_owner_pinning_forged_signal_rejection_and_owner_invalidation() {
    let mut child = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("private dbus-daemon prerequisite");
    let mut address = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let _bus = PrivateBus(child);
    let address = address.trim();
    let owner = connect(address);
    owner.request_name(BUS_NAME, false, false, true).unwrap();
    let client = Client::new(Bus::Address(address.into()), Duration::from_secs(1));
    // A normal user's mock must NEVER impersonate root, even for metadata queries.
    if unsafe { libc::geteuid() } != 0 {
        assert_eq!(client.err().unwrap().code, ErrorCode::NotAuthorized);
        return;
    }
    let mut client = client.unwrap();
    client.subscribe().unwrap();
    client.subscribe().unwrap();
    let forged = connect(address);
    signal(&forged, "SessionNew");
    for _ in 0..5 {
        assert!(
            client
                .next_event(Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
    }
    signal(&owner, "SessionNew");
    assert_eq!(
        event(&client),
        Event::SessionNew {
            sid: "0123456789abcdef0123456789abcdef".into(),
            uid: 1000
        }
    );
    signal(&owner, "SessionRemoved");
    assert_eq!(
        event(&client),
        Event::SessionRemoved {
            sid: "0123456789abcdef0123456789abcdef".into(),
            uid: 1000
        }
    );
    owner.release_name(BUS_NAME).unwrap();
    forged.request_name(BUS_NAME, false, false, true).unwrap();
    assert_eq!(event(&client), Event::OwnerReplaced);
    let error = client.list_sessions().unwrap_err();
    assert_eq!(error.code, ErrorCode::Transport);
    assert!(error.message.contains("invalidated"));
    assert!(client.subscribe().is_err()); // No silent following/rebinding to replacement.
}
