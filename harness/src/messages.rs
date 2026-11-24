//! The peer layer's rig: a moment read from the simulated clock, a sink that keeps what the
//! receiver's caller was handed, an executor that keeps what the machine's own code was given,
//! and the service tasks a case starts and stops.
//!
//! The layers have no clock and no runtime of their own — both are injected — so a case hands
//! them this clock and the machine's runtime, and time moves only when the case moves it.
//! Deliveries and executions are kept in memory: a case asserts on what its caller was handed,
//! not on a product's storage.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mahbot_peers::peer::{
    Actions, Connections, Deliveries, Delivery, Executor, Floor, Inbox, InboxError, Messages,
    Moment, QueueState, Timestamp,
};

use crate::actions::Executions;
use crate::machine::Machine;
use crate::sim::Sim;

/// The moment the message layer is told it is, before the case moves the clock: the
/// same value the other cases call `NOW`.
pub const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);

/// How many scheduler turns one wait gives the tasks before it moves the clock.
const WAIT_YIELDS: usize = 16;

/// How much virtual time one wait moves per round while it is unsatisfied.
///
/// Coarse on purpose: the clock fires every deadline on the way in order, so a wait
/// that jumps further costs nothing in precision and saves the poll budget.
const WAIT_STEP: Duration = Duration::from_millis(100);

/// The layer's moment, read from the simulated clock: the base a case composes at,
/// plus however much virtual time has passed since, plus however far the case has pushed
/// this layer's own moment.
///
/// The shift is for a case that tests a day-long retention: the layer reads one clock, so
/// a case that wants it to be three days later says so here instead of walking three days
/// of the simulation's timers.
pub struct SimMoment {
    clock: crate::clock::MockClock,
    base: Timestamp,
    shifted: Mutex<Duration>,
}

impl SimMoment {
    /// The moment a case starts this machine's layer at `base`.
    #[must_use]
    pub fn new(clock: crate::clock::MockClock, base: Timestamp) -> Self {
        Self {
            clock,
            base,
            shifted: Mutex::new(Duration::ZERO),
        }
    }

    /// Push this layer's moment `by` further, without moving the simulated clock.
    pub fn shift(&self, by: Duration) {
        *self
            .shifted
            .lock()
            .expect("the moment's shift is not poisoned") += by;
    }
}

impl Moment for SimMoment {
    fn now(&self) -> Timestamp {
        let shifted = *self
            .shifted
            .lock()
            .expect("the moment's shift is not poisoned");
        self.base.plus(self.clock.elapsed()).plus(shifted)
    }
}

/// The deliveries one machine's layer handed its caller, kept in memory.
pub struct Collected {
    delivered: Mutex<Vec<Delivery>>,
    /// Whether the sink takes what it is handed: a case that turns this off is a caller
    /// that cannot store, and the layer must offer again.
    accepting: AtomicBool,
    /// Whether the sink panics instead of taking: a caller's bug, which the layer must not
    /// let end a receiving task in silence.
    panicking: AtomicBool,
}

impl Default for Collected {
    fn default() -> Self {
        Self {
            delivered: Mutex::new(Vec::new()),
            accepting: AtomicBool::new(true),
            panicking: AtomicBool::new(false),
        }
    }
}

impl Collected {
    /// An empty sink that takes everything.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Everything delivered so far, in the order it arrived.
    #[must_use]
    pub fn deliveries(&self) -> Vec<Delivery> {
        self.lock().clone()
    }

    /// How many messages have been delivered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether nothing has been delivered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Start declining what the layer hands over, as a caller that cannot store does.
    pub fn stop_accepting(&self) {
        self.accepting.store(false, Ordering::SeqCst);
    }

    /// Take again what the layer hands over.
    pub fn start_accepting(&self) {
        self.accepting.store(true, Ordering::SeqCst);
    }

    /// Panic on the next delivery, as a caller with a bug in its own storage does.
    pub fn start_panicking(&self) {
        self.panicking.store(true, Ordering::SeqCst);
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Delivery>> {
        self.delivered
            .lock()
            .expect("the delivery sink is not poisoned")
    }
}

impl Deliveries for Collected {
    fn deliver(&self, delivery: Delivery) -> bool {
        assert!(
            !self.panicking.load(Ordering::SeqCst),
            "the case's delivery sink was told to panic"
        );
        if !self.accepting.load(Ordering::SeqCst) {
            return false;
        }
        self.lock().push(delivery);
        true
    }
}

/// One machine's peer layer, its sink, its executor and the tasks its service runs.
pub struct Messaging {
    /// The message layer itself, as the product holds it.
    pub messages: Arc<Messages>,
    /// The action layer itself, as the product holds it.
    pub actions: Arc<Actions>,
    /// The moment both layers read, which a case can push forward.
    pub moment: Arc<SimMoment>,
    /// What the message layer's caller was handed.
    pub collected: Arc<Collected>,
    /// The machine's own code, as the action layer calls it.
    pub executions: Arc<Executions>,
    /// The one reader that tells a message from an action.
    inbox: Arc<Inbox>,
    /// The endpoint this machine's own connections run over: the offer loop dials with it,
    /// so it must be the serving machine's and not the peer's.
    endpoint: quinn::Endpoint,
    tasks: Mutex<Vec<tokio::task::JoinHandle<Result<(), InboxError>>>>,
}

impl Messaging {
    /// Open `machine`'s layers over its own root, composing at [`NOW`] plus the virtual
    /// time the case has moved.
    ///
    /// # Errors
    ///
    /// The layer's refusal, as text.
    pub fn open(
        sim: &Sim,
        machine: &Machine,
        floor: Arc<dyn Floor + Send + Sync>,
    ) -> Result<Self, String> {
        let collected = Collected::new();
        let moment = Arc::new(SimMoment::new(sim.clock().clone(), NOW));
        let runtime = sim.clock().runtime();
        let executions = Executions::new(Arc::clone(&runtime));
        let messages = Arc::new(machine.messages(
            Arc::clone(&floor),
            Arc::clone(&moment) as Arc<dyn Moment + Send + Sync>,
            collected.clone(),
        )?);
        let actions = Arc::new(machine.actions(
            floor,
            Arc::clone(&moment) as Arc<dyn Moment + Send + Sync>,
            Arc::clone(&executions) as Arc<dyn Executor + Send + Sync>,
        )?);
        let inbox = Arc::new(Inbox::new(
            Arc::clone(&messages),
            Arc::clone(&actions),
            runtime,
        ));
        Ok(Self {
            messages,
            actions,
            moment,
            collected,
            executions,
            inbox,
            endpoint: machine.endpoint().map_err(|error| error.to_string())?,
            tasks: Mutex::new(Vec::new()),
        })
    }

    /// Run the pair's service: offer what is queued, and answer both messages and actions.
    ///
    /// The handle is kept: a case that wants to see how the service ended asks
    /// [`Self::endings`], and dropping the layer stops it.
    pub fn serve(&self, connections: &Arc<Connections>, peer: &Machine) {
        let peer_id = peer.peer_id();
        let handle = tokio::spawn(Arc::clone(&self.inbox).serve(
            Arc::clone(connections),
            self.endpoint.clone(),
            peer_id,
        ));
        self.tasks().push(handle);
    }

    /// Stop every service this case started, as a product that stops serving a peer does.
    ///
    /// The layer stays open: [`Self::serve`] starts a fresh service over the same root.
    pub fn stop(&self) {
        for task in self.tasks().drain(..) {
            task.abort();
        }
    }

    /// Wait for every service this case started, and answer how each one ended.
    ///
    /// A service that met a queue, memory, record or log it could not read or write ends with
    /// that refusal rather than going on answering nothing, so this is how a case sees it.
    pub async fn endings(&self) -> Vec<Result<(), String>> {
        let tasks: Vec<_> = self.tasks().drain(..).collect();
        let mut endings = Vec::with_capacity(tasks.len());
        for task in tasks {
            endings.push(match task.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(error.to_string()),
                Err(error) => Err(error.to_string()),
            });
        }
        endings
    }

    fn tasks(&self) -> MutexGuard<'_, Vec<tokio::task::JoinHandle<Result<(), InboxError>>>> {
        self.tasks
            .lock()
            .expect("the service tasks are not poisoned")
    }
}

impl Drop for Messaging {
    fn drop(&mut self) {
        for task in self.tasks().drain(..) {
            task.abort();
        }
    }
}

/// Wait until `count` messages have been delivered, letting the clock move.
///
/// # Errors
///
/// The count was not reached within `budget` of virtual time.
pub async fn wait_for(
    sim: &Sim,
    collected: &Collected,
    count: usize,
    budget: Duration,
) -> Result<Vec<Delivery>, String> {
    let mut spent = Duration::ZERO;
    loop {
        for _ in 0..WAIT_YIELDS {
            if collected.len() >= count {
                return Ok(collected.deliveries());
            }
            tokio::task::yield_now().await;
        }
        if spent >= budget {
            return Err(format!(
                "{} of {count} messages were delivered within {budget:?} of virtual time",
                collected.len()
            ));
        }
        let step = WAIT_STEP.min(budget - spent);
        sim.clock().advance(step).await;
        spent += step;
    }
}

/// Wait until `peer`'s queue is in the state `holds`, letting the clock move.
///
/// # Errors
///
/// The state was not reached within `budget` of virtual time, or the layer refused to
/// answer.
pub async fn wait_for_state(
    sim: &Sim,
    messages: &Messages,
    peer: &mahbot_peers::identity::PeerId,
    holds: impl Fn(&QueueState) -> bool,
    budget: Duration,
) -> Result<QueueState, String> {
    let mut spent = Duration::ZERO;
    loop {
        let state = messages.state(peer).map_err(|error| error.to_string())?;
        if holds(&state) {
            return Ok(state);
        }
        if spent >= budget {
            return Err(format!(
                "the queue was `{state:?}` after {budget:?} of virtual time, not the state the \
                 case waits for"
            ));
        }
        for _ in 0..WAIT_YIELDS {
            tokio::task::yield_now().await;
        }
        let step = WAIT_STEP.min(budget - spent);
        sim.clock().advance(step).await;
        spent += step;
    }
}
