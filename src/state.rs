use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use mongodb::Client as MongoClient;
use oauth2::basic::BasicClient;
use tower_cookies::Key;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub options: LeptosOptions,
    pub db_client: MongoClient,
    pub google_oauth_client: BasicClient,
    pub cookie_key: Key,
}
