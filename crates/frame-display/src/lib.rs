#![doc = include_str!("../README.md")]

pub mod descriptor;
pub mod format;
pub mod registry;
pub mod render;
pub mod review;
pub mod typed;
pub mod value;

pub use registry::Registry;
pub use render::{Rules, render, render_typed};
pub use review::{Gap, GapKind, Line, Review, Section, Signs};
