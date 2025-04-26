use serde::{Deserialize, Serialize};

pub mod app;
#[cfg(feature = "ssr")]
pub mod auth;
#[cfg(feature = "ssr")]
pub mod db;
#[cfg(feature = "ssr")]
pub mod models;
#[cfg(feature = "ssr")]
pub mod state;

// Used to transport essential user info to the client safely
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct UserClientInfo {
    pub email: String,
    pub name: String,
    // Don't include sensitive IDs here
}

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}
