//! latch v2 management TUI (G1-G9, AR8): Elm-style — `model` holds all
//! state, `update` is pure and emits commands, `exec` is the only module
//! that calls latch-core (the same functions the CLI uses), `view`
//! renders, `app` owns the terminal. Snapshot tests drive `update` and
//! render `view` on a TestBackend without any terminal.

pub mod app;
pub mod exec;
pub mod model;
pub mod update;
pub mod view;

pub use app::run;
