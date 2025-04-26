#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use std::env;

    use axum::routing::get;
    use axum::Router;
    use leptos::logging::log;
    use leptos::prelude::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};
    use leptos_test::app::*;
    use leptos_test::auth::{
        google_auth_callback_handler, google_login_handler, setup_google_oauth_client,
    };
    use leptos_test::db::connect_db;
    use leptos_test::state::AppState;
    use tower_cookies::{CookieManagerLayer, Key};

    match dotenvy::dotenv() {
        Ok(_) => println!("Loaded .env file"),
        Err(_) => println!("No .env file found, relying on environment variables"),
    }

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;
    let db_client = connect_db().await.expect("Failed to connect to MongoDB");
    let google_oauth_client =
        setup_google_oauth_client().expect("Failed to setup Google OAuth client");
    let cookie_secret =
        env::var("COOKIE_SECRET_KEY").expect("COOKIE_SECRET_KEY must be set for signing cookies");
    let key = Key::from(cookie_secret.as_bytes());
    let app_state = AppState {
        options: leptos_options.clone(),
        db_client: db_client.clone(), // Clone client for state
        google_oauth_client,
        cookie_key: key.clone(), // Clone key for state
    };
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);
    for route in routes.clone().into_iter() {
        log!("route: {}", route.path());
    }

    let app = Router::new()
        .route("/login/google", get(google_login_handler))
        .route("/auth/google/callback", get(google_auth_callback_handler))
        .leptos_routes_with_context(
            &app_state,
            routes,
            {
                move || {
                    provide_context(db_client.clone()); // Provide DB client to server functions/rendering
                    provide_context(key.clone()); // Provide Cookie Key to server functions/rendering
                }
            },
            {
                let leptos_options = leptos_options.clone();
                move || shell(leptos_options.clone())
            },
        )
        .fallback(leptos_axum::file_and_error_handler::<AppState, _>(shell))
        .layer(CookieManagerLayer::new())
        .with_state(app_state);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
}
