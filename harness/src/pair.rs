//! A mediator: a party with its own key that sits between two machines.
//!
//! The case it exists for is the one commit-then-reveal is supposed to make
//! impossible: a machine that is given the mediator's fingerprint instead of the
//! other machine's runs one ceremony with it, while the mediator runs a second
//! ceremony with the other machine. Nothing is tampered with — the mediator holds
//! its own key, so the two transcripts genuinely differ — and the two people,
//! comparing their own strings with each other, see different values.
//!
//! The mediator plays along: it confirms its own comparison on both sides. What
//! makes the case meaningful is the people on the two machines, who reject. The
//! mediator therefore records nothing and proves nothing on its own; it is the
//! rig's way to put a real second key in the middle.

use std::sync::Arc;

use mahbot_peers::beacon::{Beacon, Session};
use mahbot_peers::identity::{Fingerprint, Identity, PeerId};
use mahbot_peers::peer::PAIR_FLIGHT_TIMEOUT;
use mahbot_peers::peer::pair::{Ceremony, Comparison, Outcome, Turn};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig};

use crate::beacon::TestBeacon;
use crate::sim::Sim;

/// A mediator with its own identity, its own address and a live beacon session.
pub struct Mediator {
    identity: Identity,
    session: Session,
}

/// What the mediator saw and how each side's ceremony ended.
#[derive(Debug)]
pub struct Interposed {
    /// The string the machine on the left showed its person.
    pub left: Option<Comparison>,
    /// The string the machine on the right showed its person.
    pub right: Option<Comparison>,
    pub left_outcome: Outcome,
    pub right_outcome: Outcome,
}

impl Mediator {
    /// Build a mediator with a fresh identity, at its own address on the link, and
    /// register it at `beacon` so machines can address it.
    pub async fn new(sim: &Sim, beacon: &TestBeacon) -> Result<Self, String> {
        let identity = crate::root::detached_identity().map_err(|error| error.to_string())?;
        let socket = sim.link().attach_next();
        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            Arc::clone(&socket) as Arc<dyn AsyncUdpSocket>,
            sim.clock().runtime(),
        )
        .map_err(|error| error.to_string())?;
        let client = Beacon::new(
            endpoint,
            sim.clock().runtime(),
            beacon.address(),
            beacon.key(),
            identity.clone(),
        );
        let session = client.connect().await.map_err(|error| error.to_string())?;
        session
            .register()
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self { identity, session })
    }

    /// The fingerprint a machine is (wrongly) given when it is meant to pair with
    /// the other machine.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    /// The mediator's own id.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// Sit between `left` and `right`: answer `left`'s ceremony and start one with
    /// `right`, confirming both.
    ///
    /// Returns both comparisons, so a case can show they differ. The mediator
    /// decides nothing about trust; it is the two machines' people who do.
    pub async fn interpose(&self, left: PeerId, right: PeerId) -> Result<Interposed, String> {
        let me = self.identity.peer_id();
        let address = self
            .session
            .observed_address()
            .await
            .map_err(|error| error.to_string())?;
        let (mut right_ceremony, first) =
            Ceremony::initiate(me, right.fingerprint(), Some(address), false)
                .map_err(|error| error.to_string())?;
        self.session
            .introduce(right, &first)
            .await
            .map_err(|error| error.to_string())?;
        let mut left_ceremony: Option<Ceremony> = None;
        let mut left_comparison = None;
        let mut right_comparison = None;
        let mut left_outcome = None;
        let mut right_outcome = None;
        while left_outcome.is_none() || right_outcome.is_none() {
            let introduction = self
                .session
                .next_introduction_within(PAIR_FLIGHT_TIMEOUT)
                .await
                .map_err(|error| error.to_string())?
                .ok_or("the mediator waited out a ceremony flight")?;
            let from = introduction.from();
            if from == left {
                let turn = match left_ceremony.as_mut() {
                    None => {
                        let (ceremony, turn) =
                            Ceremony::respond(me, &introduction, Some(address), false)
                                .map_err(|error| error.to_string())?;
                        left_ceremony = Some(ceremony);
                        turn
                    }
                    Some(ceremony) => ceremony
                        .receive(introduction.payload())
                        .map_err(|error| error.to_string())?,
                };
                let ceremony = left_ceremony
                    .as_mut()
                    .expect("the left ceremony is set before it is answered");
                if let Some(outcome) = self
                    .answer(left, turn, ceremony, &mut left_comparison)
                    .await?
                {
                    left_outcome = Some(outcome);
                }
            } else if from == right {
                let turn = right_ceremony
                    .receive(introduction.payload())
                    .map_err(|error| error.to_string())?;
                if let Some(outcome) = self
                    .answer(right, turn, &mut right_ceremony, &mut right_comparison)
                    .await?
                {
                    right_outcome = Some(outcome);
                }
            }
        }
        Ok(Interposed {
            left: left_comparison,
            right: right_comparison,
            left_outcome: left_outcome.expect("both ceremonies ended"),
            right_outcome: right_outcome.expect("both ceremonies ended"),
        })
    }

    /// Send what a turn asks for and confirm its comparison, as a party that
    /// plays along does.
    async fn answer(
        &self,
        to: PeerId,
        turn: Turn,
        ceremony: &mut Ceremony,
        comparison: &mut Option<Comparison>,
    ) -> Result<Option<Outcome>, String> {
        if let Some(bytes) = turn.send {
            self.session
                .introduce(to, &bytes)
                .await
                .map_err(|error| error.to_string())?;
        }
        if let Some(shown) = turn.show {
            *comparison = Some(shown);
            let answer = ceremony.confirm(true).map_err(|error| error.to_string())?;
            if let Some(bytes) = answer.send {
                self.session
                    .introduce(to, &bytes)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            return Ok(answer.outcome);
        }
        Ok(turn.outcome)
    }
}
