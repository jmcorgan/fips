//! The Android names for the radio-bridge backend.
//!
//! The backend Android embedders drive now lives in [`super::io_radio`], under
//! platform-neutral names, so that another platform whose radio is driven
//! through commands and callbacks can share it. The names an embedder was
//! written against are kept here so that moving the code did not break the
//! embedder API.

pub use super::io_radio::{
    BleRadio as AndroidRadio, BleRadioBridge as AndroidBleBridge, BleRadioSlot,
    RadioAcceptor as AndroidAcceptor, RadioIo as AndroidIo, RadioScanner as AndroidScanner,
    RadioStream as AndroidStream,
};
