//! The one place a pair's connection is read: accept a stream, decide whose frame it is, and
//! hand it to the layer that owns it.
//!
//! A pair's connection carries one bidirectional stream per message offer, one per action
//! request, and the binding exchange's first stream. [`Inbox::serve`] runs the receiving half of
//! both services for one peer: it watches the pair's live connection, starts one reader per
//! connection, and hands every stream after the binding exchange to [`Messages`] or [`Actions`]
//! by the frame's magic. A message is therefore never taken for an action nor an action for a
//! message, in either direction, and neither service can starve or misread the other.
//!
//! The same task also runs the message layer's offer loop, so one service per peer answers both
//! and one ending reaches whoever started it. It compacts the action memory every `SWEEP_EVERY`;
//! the clearing itself is the record's, so a person's trust withdrawal makes everything recorded
//! before its moment gone on the next look, whether or not this task ever runs. The two halves
//! share one fault: a queue, record or log this machine cannot read or write ends the service
//! instead of being stepped over, and a connection that does not present the peer's key ends it
//! rather than receiving nothing under the pair's name.
//!
//! # Why one reader
//!
//! QUIC hands each incoming stream to one `accept_bi` caller, and two callers race: a stream
//! could be accepted by the wrong service. The binding exchange owns the first stream a kept
//! connection carries — the inbox waits for [`Traffic::exchange_done`] before accepting — and
//! this module owns every stream after it. The source invariants `peer.one_stream_acceptor` and
//! `peer.one_acceptor_per_file` keep a third caller, and a second one in either file, from
//! appearing.
//!
//! # What a stream's first bytes decide
//!
//! Both request magics start with `mahbot-peer-`, so the reader reads a short prefix before it
//! knows the frame. A prefix that starts with the action magic is an action; everything else is
//! a message, which is also what a frame this build cannot read is answered as. The prefix read
//! is bounded as a whole, and the layer that owns the frame reads the rest under its own budget.
//! A stream that never completes its prefix spends that one bound and a task, bounded again by
//! the transport's concurrent-stream limit; the bytes it did carry classify it, a message unless
//! they are the action magic, and it is counted against that service's window before the rest of
//! the frame is read. A window is a service's own, so a flood of actions cannot throttle the
//! same peer's messages.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::{RecvStream, Runtime, SendStream};

use crate::beacon::{sleep, timeout};
use crate::identity::{Fingerprint, PeerId};
use crate::peer::actions::{ACTION_MAGIC, ActionError, Actions};
use crate::peer::connect::{Connections, Traffic, presented};
use crate::peer::messages::{MessageError, Messages};
use crate::peer::stream;
use crate::peer::sweep::Due;

/// How often the inbox looks at the pair's connection for a change.
const INBOX_POLL: Duration = Duration::from_secs(1);

/// How often a connection's reader wakes with nothing to read, so it can notice that the
/// service that started it has stopped.
const RECEIVER_IDLE: Duration = Duration::from_secs(10);

/// The receiving half of one machine's peer layer.
///
/// Built once per storage root, like the layers it reads, and run once per paired peer. A
/// product that wants messages alone still builds an [`Actions`] over the same root; its
/// executor is never called unless a peer sends an action.
pub struct Inbox {
    messages: Arc<Messages>,
    actions: Arc<Actions>,
    runtime: Arc<dyn Runtime>,
}

impl fmt::Debug for Inbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inbox")
            .field("messages", &self.messages)
            .field("actions", &self.actions)
            .finish_non_exhaustive()
    }
}

impl Inbox {
    /// Build the inbox over the two layers and the runtime they answer on.
    ///
    /// The two layers must be opened with the **same** [`Floor`](crate::peer::Floor) and the
    /// same [`Moment`](crate::peer::Moment): a product that wires a different floor into each
    /// gets messages and actions judged by different host policies, and one that wires two
    /// clocks measures a single peer's acts against two different presents. `runtime` must be
    /// the one both layers were opened with, so the inbox's prefix and stream waits and each
    /// layer's own timeouts are measured by the same executor. The inbox cannot check any of
    /// this — the layers hold trait objects — so it is the caller's obligation.
    #[must_use]
    pub fn new(messages: Arc<Messages>, actions: Arc<Actions>, runtime: Arc<dyn Runtime>) -> Self {
        Self {
            messages,
            actions,
            runtime,
        }
    }

    /// Serve one peer: offer its queued messages and answer both services.
    ///
    /// An infinite loop, one per paired peer, run by the caller. Each round notices whether the
    /// pair's connection changed and starts a reader for the new one; the message layer's offer
    /// loop runs in the same task. A fault either half meets — a queue, memory, record or log
    /// this machine cannot read or write, or a connection that does not present the peer's key —
    /// ends the service and is returned to whoever started it.
    ///
    /// Dropping this future stops the readers it started: every wait the crate makes in them is
    /// bounded, so they reach the top of their loop and find the service gone. The waits that
    /// are not the crate's are the caller's own: the message layer's delivery sink, the action
    /// layer's executor, and the audit log's cross-process lock. A stream's own task runs on the
    /// injected runtime, so a slow action holds its stream and no other.
    ///
    /// # Errors
    ///
    /// The first refusal either half met, in its own words.
    pub async fn serve(
        self: Arc<Self>,
        connections: Arc<Connections>,
        peer: PeerId,
    ) -> Result<(), InboxError> {
        let running = Arc::new(AtomicBool::new(true));
        let _stop = Stopping(Arc::clone(&running));
        let fault = Fault::default();
        let reader = Arc::clone(&self).read(
            Arc::clone(&connections),
            peer,
            Arc::clone(&running),
            fault.clone(),
        );
        let messages = Arc::clone(&self.messages);
        let offer = async move {
            messages
                .offer_loop(Arc::clone(&connections), peer)
                .await
                .map_err(InboxError::Messages)
        };
        stream::either(reader, offer).await
    }

    /// Watch the pair's connection and start one reader per connection.
    async fn read(
        self: Arc<Self>,
        connections: Arc<Connections>,
        peer: PeerId,
        running: Arc<AtomicBool>,
        fault: Fault,
    ) -> Result<(), InboxError> {
        let mut watched: Option<Traffic> = None;
        let mut swept = Due::default();
        loop {
            // A person's trust withdrawal is the way out of a full action journal, so the
            // memory goes with the trust. The sweep is here, not in the action layer's own
            // service, because the inbox is the one service a product runs per peer.
            let now = self.actions.now();
            if swept.due(now) {
                // A memory another writer holds this instant is compacted on a later round;
                // it must not end the service the peer is served by.
                match self.actions.sweep(&peer) {
                    Ok(()) | Err(ActionError::Busy { .. }) => {}
                    Err(error) => return Err(InboxError::Actions(error)),
                }
            }
            if let Some(error) = fault.take() {
                return Err(error);
            }
            if !running.load(Ordering::SeqCst) {
                return Ok(());
            }
            let Some(traffic) = connections.traffic(&peer) else {
                sleep(&*self.runtime, INBOX_POLL).await;
                continue;
            };
            // The binding exchange owns the first stream a kept connection carries: a reader
            // that started before it would take the exchange's stream for a message.
            if !traffic.exchange_done() {
                sleep(&*self.runtime, INBOX_POLL).await;
                continue;
            }
            if !watched.as_ref().is_some_and(|seen| seen.same(&traffic)) {
                watched = Some(traffic.clone());
                self.runtime.spawn(Box::pin(reader(
                    Arc::clone(&self),
                    Arc::clone(&connections),
                    peer,
                    traffic,
                    Arc::clone(&running),
                    fault.clone(),
                )));
            }
            sleep(&*self.runtime, INBOX_POLL).await;
        }
    }

    /// Read one stream's prefix and hand the frame to the layer that owns it.
    async fn answer_stream(
        self: Arc<Self>,
        peer: PeerId,
        send: SendStream,
        mut recv: RecvStream,
        fault: Fault,
    ) {
        let prefix = stream::read_prefix(&*self.runtime, &mut recv).await;
        let result = if prefix.starts_with(ACTION_MAGIC) {
            self.actions
                .receive(peer, send, recv, prefix)
                .await
                .map_err(InboxError::Actions)
        } else {
            self.messages
                .receive(peer, send, recv, prefix)
                .await
                .map_err(InboxError::Messages)
        };
        if let Err(error) = result {
            fault.set(error);
        }
    }
}

/// One connection's reader: accept a stream, start its task, repeat.
async fn reader(
    inbox: Arc<Inbox>,
    connections: Arc<Connections>,
    peer: PeerId,
    traffic: Traffic,
    running: Arc<AtomicBool>,
    fault: Fault,
) {
    let connection = traffic.connection().clone();
    let presented = presented(&connection);
    if presented != Some(peer.fingerprint()) {
        // Nothing read on this connection could be attributed to the pair, so the service ends
        // with that refusal rather than receiving nothing for the connection's life.
        fault.set(InboxError::WrongPeer { peer, presented });
        return;
    }
    while running.load(Ordering::SeqCst) {
        let accepted = timeout(&*inbox.runtime, RECEIVER_IDLE, connection.accept_bi()).await;
        let (send, recv) = match accepted {
            // The idle wait passed with nothing to read: check whether the service is still
            // there and wait again.
            None => continue,
            Some(Ok(streams)) => streams,
            // The connection is closed: there is nothing left to read on it.
            Some(Err(_)) => return,
        };
        if !connections.is_live(&peer, &traffic) {
            return;
        }
        // One stream, one task: a slow action or a caller's slow sink holds its own stream, and
        // a repeat that arrives while the first execution is still running is answered by its
        // own task rather than waiting behind it.
        inbox.runtime.spawn(Box::pin(inbox.clone().answer_stream(
            peer,
            send,
            recv,
            fault.clone(),
        )));
    }
}

/// The first fault a reader or a stream task met, for the service to return.
#[derive(Clone, Default)]
struct Fault(Arc<Mutex<Option<InboxError>>>);

impl Fault {
    fn take(&self) -> Option<InboxError> {
        self.0
            .lock()
            .expect("the inbox's fault is not poisoned")
            .take()
    }

    fn set(&self, error: InboxError) {
        let mut slot = self.0.lock().expect("the inbox's fault is not poisoned");
        if slot.is_none() {
            *slot = Some(error);
        }
    }
}

/// Flips the readers' flag when the service that started them is dropped.
struct Stopping(Arc<AtomicBool>);

impl Drop for Stopping {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Why the inbox stopped serving a pair.
#[derive(Debug)]
pub enum InboxError {
    /// The message layer refused, in its own words.
    Messages(MessageError),
    /// The action layer refused, in its own words.
    Actions(ActionError),
    /// The pair's connection presents a key that is not the peer's, or none at all. Nothing
    /// read on it could be attributed to the pair, so the service ends instead of receiving
    /// nothing for the connection's life.
    WrongPeer {
        /// The peer the service was started for.
        peer: PeerId,
        /// The key the connection presented, if any.
        presented: Option<Fingerprint>,
    },
}

impl fmt::Display for InboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Messages(error) => error.fmt(f),
            Self::Actions(error) => error.fmt(f),
            Self::WrongPeer { peer, presented } => {
                let presented =
                    presented.map_or_else(|| "no key".to_owned(), |key| key.to_string());
                write!(
                    f,
                    "the connection for {} presents {presented}, not the peer",
                    peer.fingerprint()
                )
            }
        }
    }
}

impl std::error::Error for InboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Messages(error) => Some(error),
            Self::Actions(error) => Some(error),
            Self::WrongPeer { .. } => None,
        }
    }
}
