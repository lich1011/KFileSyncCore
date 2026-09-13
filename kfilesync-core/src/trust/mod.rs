//! Zero-trust decision engine.
//!
//! Every mutating inbound request flows through [`trust_evaluator::evaluate_inbound`]
//! before the host runs the business handler. This is the single source of
//! truth for the five anti-replay / trust rules.
//!
//! See ADR-011 and `CORE_EXTRACTION_DESIGN.md` §3.4 for the rule table.

pub mod cert_pin;
pub mod pairing_state;
pub mod replay_guard;
pub mod trust_evaluator;
