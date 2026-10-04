//! A custom [`Listener`]: serve an agent in-process, with connections handed
//! over a channel instead of accepted on a socket file. Useful in tests, or
//! to embed an agent in a program that talks to it directly.
//!
//! The example then speaks the agent protocol by hand: it adds a key, lists
//! it, signs with it and checks the signature. It needs no OpenSSH tools.
//!
//! ```sh
//! cargo run --example in-process
//! ```
//!
//! [`UnixStream`] already implements [`Stream`](ssh_agent_kit::Stream); a
//! transport of your own implements that too.

use ssh_agent_kit::ssh_key::private::Ed25519Keypair;
use ssh_agent_kit::ssh_key::{PublicKey, Signature};
use ssh_agent_kit::wire::{self, read_frame, write_frame};
use ssh_agent_kit::{Agent, Listener, serve, verify};
use ssh_encoding::{Decode, Encode};
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};

/// Accepts the server ends of connections sent down a channel.
struct ChannelListener(Mutex<Receiver<UnixStream>>);

impl Listener for ChannelListener {
    type Stream = UnixStream;

    /// [`serve`] polls: answer `WouldBlock` while no connection waits.
    fn accept(&self) -> io::Result<UnixStream> {
        match self.0.lock().unwrap().try_recv() {
            Ok(stream) => Ok(stream),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
    }
}

/// Open a connection to the in-process agent.
fn connect(connections: &Sender<UnixStream>) -> io::Result<UnixStream> {
    let (client, server) = UnixStream::pair()?;
    connections.send(server).map_err(io::Error::other)?;
    Ok(client)
}

/// Send one request and return the reply body.
fn request(stream: &mut UnixStream, body: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    write_frame(stream, body)?;
    Ok(read_frame(stream)?.ok_or("agent closed the connection")?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (connections, incoming) = channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = {
        let listener = ChannelListener(Mutex::new(incoming));
        let shutdown = Arc::clone(&shutdown);
        std::thread::spawn(move || serve(listener, Arc::new(Agent::new()), shutdown))
    };

    let mut agent = connect(&connections)?;

    // `ssh-add FILE`: SSH2_AGENTC_ADD_IDENTITY with the key type, the key
    // and its comment.
    let pair = Ed25519Keypair::from_seed(&[7; 32]);
    let public = PublicKey::new(pair.public.into(), "in-process@example.com");
    let mut add = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
    "ssh-ed25519".encode(&mut add)?;
    pair.encode(&mut add)?;
    public.comment().encode(&mut add)?;
    assert_eq!(request(&mut agent, &add)?, wire::success());

    // `ssh-add -L`: the identities answer is a count, then blob and comment
    // pairs.
    let reply = request(&mut agent, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES])?;
    let mut r = &reply[1..];
    for _ in 0..u32::decode(&mut r)? {
        let blob = Vec::<u8>::decode(&mut r)?;
        let comment = String::decode(&mut r)?;
        let key = PublicKey::from_bytes(&blob)?;
        println!("listed: {} {comment}", key.fingerprint(Default::default()));
    }

    // A sign request: key blob, data, flags. The reply holds the signature.
    let data = b"signed in-process";
    let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
    public.to_bytes()?.encode(&mut sign)?;
    data.as_slice().encode(&mut sign)?;
    0u32.encode(&mut sign)?;
    let reply = request(&mut agent, &sign)?;
    assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
    let mut r = &reply[1..];
    let signature = Signature::try_from(Vec::<u8>::decode(&mut r)?.as_slice())?;
    verify(&public, data, &signature)?;
    println!("signature verified: {}", signature.algorithm());

    drop(agent);
    shutdown.store(true, Ordering::SeqCst);
    server.join().expect("server thread")?;
    Ok(())
}
