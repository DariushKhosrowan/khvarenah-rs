//! View implementations for the DastYab GUI.
//!
//! Each view is a panel rendered by the app shell. They read from the app's
//! [`GuiState`] cache and drive store mutations through the async bridge,
//! reusing the dialog helpers.
//!
//! The palette constants live in `crate::app` and are re-exported here so the
//! views read them from one place.

pub mod history;
pub mod profiles;
pub mod tokens;

pub use crate::app::{GOLD, GOLD_DIM, PANEL, TEXT};
