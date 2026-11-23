//! The action layer's rig: an executor that records what it was handed and can run, decline,
//! panic, take its time, or change the root before it answers.
//!
//! The layer has no clock and no executor of its own — both are injected — so a case hands it
//! this rig and the machine's runtime, and an execution moves only when the case moves the
//! clock. What a caller was told is the [`mahbot_peers::peer::ActionAnswer`] the request
//! returned; what the receiving machine's own code was handed is kept here, so a case asserts
//! on both.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mahbot_peers::identity::PeerId;
use mahbot_peers::peer::{Executed, Execution, ExecutionFuture, Executor};
use quinn::Runtime;

/// What the case's own code does with one action.
#[derive(Clone, Debug)]
pub enum Behaviour {
    /// It ran, and this is what came back.
    Run(Vec<u8>),
    /// It declined to run it.
    Decline,
    /// It panicked, as a bug in the product's own code does.
    Panic,
    /// It panicked before it returned a future, as a bug in the product's own code can.
    PanicEagerly,
    /// It is still running until this much virtual time passes, then answers.
    Hold {
        /// How long it takes.
        by: Duration,
        /// What it answers when it finishes.
        result: Vec<u8>,
    },
}

/// One machine's executor, and the actions it was handed.
pub struct Executions {
    runtime: Arc<dyn Runtime>,
    /// The behaviour for a peer, or the default under `None`.
    behaviour: Mutex<BTreeMap<Option<PeerId>, Behaviour>>,
    handed: Mutex<Vec<Execution>>,
    /// What the machine's own code does before it answers, if a case set it: the window
    /// between the layer's remember and its run, where a case can change the root underneath.
    before_answer: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl Executions {
    /// An executor that declines everything until a case says otherwise.
    #[must_use]
    pub fn new(runtime: Arc<dyn Runtime>) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            behaviour: Mutex::new(BTreeMap::new()),
            handed: Mutex::new(Vec::new()),
            before_answer: Mutex::new(None),
        })
    }

    /// Run every action, answering this result.
    pub fn run(&self, result: impl Into<Vec<u8>>) {
        self.set(None, Behaviour::Run(result.into()));
    }

    /// Run every action from `peer`, answering this result.
    pub fn run_for(&self, peer: &PeerId, result: impl Into<Vec<u8>>) {
        self.set(Some(*peer), Behaviour::Run(result.into()));
    }

    /// Decline every action.
    pub fn decline(&self) {
        self.set(None, Behaviour::Decline);
    }

    /// Panic on every action.
    pub fn panic(&self) {
        self.set(None, Behaviour::Panic);
    }

    /// Panic before returning a future, on every action.
    pub fn panic_eagerly(&self) {
        self.set(None, Behaviour::PanicEagerly);
    }

    /// Take `by` of virtual time before answering every action.
    pub fn hold(&self, by: Duration, result: impl Into<Vec<u8>>) {
        self.set(
            None,
            Behaviour::Hold {
                by,
                result: result.into(),
            },
        );
    }

    /// Take `by` of virtual time before answering every action from `peer`.
    pub fn hold_for(&self, peer: &PeerId, by: Duration, result: impl Into<Vec<u8>>) {
        self.set(
            Some(*peer),
            Behaviour::Hold {
                by,
                result: result.into(),
            },
        );
    }

    /// Do `hook` inside the machine's own code, before it answers every action.
    ///
    /// This is the window between the layer's remember and its run, where a case can damage
    /// the root and prove what the layer answers before a storage fault ends the service.
    pub fn before_answer(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self
            .before_answer
            .lock()
            .expect("the executor's hook is not poisoned") = Some(Arc::new(hook));
    }

    /// Everything the machine's own code was handed, in the order it arrived.
    #[must_use]
    pub fn handed(&self) -> Vec<Execution> {
        self.lock().clone()
    }

    /// How many actions the machine's own code was handed.
    #[must_use]
    pub fn count(&self) -> usize {
        self.lock().len()
    }

    fn set(&self, peer: Option<PeerId>, behaviour: Behaviour) {
        self.behaviour
            .lock()
            .expect("the executor's behaviour is not poisoned")
            .insert(peer, behaviour);
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Execution>> {
        self.handed
            .lock()
            .expect("the executed actions are not poisoned")
    }

    fn behaviour_for(&self, peer: &PeerId) -> Behaviour {
        let behaviour = self
            .behaviour
            .lock()
            .expect("the executor's behaviour is not poisoned");
        behaviour
            .get(&Some(*peer))
            .or_else(|| behaviour.get(&None))
            .cloned()
            .unwrap_or(Behaviour::Decline)
    }
}

impl Executor for Executions {
    fn execute(&self, action: Execution) -> ExecutionFuture<'_> {
        let behaviour = self.behaviour_for(&action.peer);
        self.lock().push(action);
        let hook = self
            .before_answer
            .lock()
            .expect("the executor's hook is not poisoned")
            .clone();
        if let Some(hook) = hook {
            hook();
        }
        match behaviour {
            // An eager panic happens before a future exists, so it is raised here rather than
            // in one.
            Behaviour::PanicEagerly => {
                panic!("the case's executor was told to panic before answering")
            }
            Behaviour::Panic => Box::pin(async { panic!("the case's executor was told to panic") }),
            Behaviour::Run(result) => Box::pin(async move { Executed::Ran { result } }),
            Behaviour::Decline => Box::pin(async { Executed::Declined }),
            Behaviour::Hold { by, result } => {
                let mut timer = self.runtime.new_timer(self.runtime.now() + by);
                Box::pin(async move {
                    std::future::poll_fn(|context| timer.as_mut().poll(context)).await;
                    Executed::Ran { result }
                })
            }
        }
    }
}

impl std::fmt::Debug for Executions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executions")
            .field("handed", &self.count())
            .finish_non_exhaustive()
    }
}
