use std::fmt::Debug;

#[cfg(not(feature = "parallel"))]
pub trait Element: Clone + Debug + Default {}

#[cfg(not(feature = "parallel"))]
impl<T: Clone + Debug + Default> Element for T {}

#[cfg(feature = "parallel")]
pub trait Element: Clone + Debug + Default + Send + Sync {}

#[cfg(feature = "parallel")]
impl<T: Clone + Debug + Default + Send + Sync> Element for T {}
