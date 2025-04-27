use leptos::{logging::log, prelude::*};
use leptos_meta::{provide_meta_context, Link, MetaTags, Stylesheet, Title};
use leptos_router::{
    components::{Route, Router, Routes, A},
    hooks::use_navigate,
    path, NavigateOptions,
};

use crate::UserClientInfo;

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body class="bg-gray-900">
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    // Resource to fetch authentication status
    let logout_action = ServerAction::<Logout>::new();
    let user_resource = Resource::new(
        move || logout_action.version().get(),
        |_| async move { check_auth().await },
    );

    // Handle logout result (e.g., redirect on success)
    Effect::new(move |_| {
        if let Some(Ok(())) = logout_action.value().get() {
            // Successfully logged out on the server, now redirect client-side
            let navigate = use_navigate();
            navigate("/", NavigateOptions::default()); // Or maybe /login
            user_resource.refetch(); // Refetch user status after logout
        } else if let Some(Err(e)) = logout_action.value().get() {
            log!("logout error: {:?}", e);
        }
        // Handle logout error? Show a message?
    });

    view! {
        <Stylesheet id="leptos" href="/pkg/leptos-test.css"/>
        <Link rel="shortcut icon" type_="image/ico" href="/favicon.ico"/>
        <Title text="Leptos SSR + Auth + MongoDB"/>

        <Router>
            <header class="text-gray-100 bg-gray-800">
                <div class="flex justify-center items-center">
                    <h1 class="text-4xl font-extrabold">"My App"</h1>
                </div>
                <nav class="pb-2 pl-2">
                    <A href="/">"Home"</A> " | "
                    <Transition fallback=move || view! { <span>"Loading..."</span>}>
                        {move || match user_resource.get() {
                            Some(Ok(Some(user))) => view! {
                                <span>{format!("Logged in as {}", user.name)}</span> " | "
                                <button class="text-gray-900 bg-gray-300 px-1 rounded" on:click=move |_| {logout_action.dispatch(Logout {});}>"Logout"</button>
                            }.into_any(),
                            Some(Ok(None)) => view! { <button class="text-gray-900 bg-gray-300 rounded px-1" on:click=move |_| {window().location().replace("/login/google").unwrap();}>Login</button> }.into_any(),
                            Some(Err(_)) => view! {/*  <span class="error">{format!("Auth Error: {}", e)}</span>  */}.into_any(),
                            None => view! { <span>"Checking..."</span> }.into_any(), // Loading state
                        }}
                    </Transition>
                </nav>
            </header>
            <hr/>
            <main>
                <Routes fallback=NotFound>
                    <Route path=path!("/") view=move || {
                        view! {
                            <div class="text-gray-100">
                                <Transition fallback=move || view!{<p>"Loading user..."</p>}>
                                {move || user_resource.get().map(|res| match res {
                                     Ok(Some(user)) => view! { <UserProfile user=user /> }.into_any(),
                                     Ok(None) => view! { <LoginPage user_resource=user_resource/> }.into_any(),
                                     Err(e) => view! { <p class="error">"Error loading user: " {e.to_string()}</p> }.into_any()
                                })}
                                </Transition>
                            </div>
                        }
                    }/>
                    <Route path=path!("/login") view=move || view! {<LoginPage user_resource=user_resource/>} />
                    // Add other routes here
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn LoginPage(
    user_resource: Resource<Result<Option<UserClientInfo>, ServerFnError>>,
) -> impl IntoView {
    Effect::new(move |_| {
        if let Some(Ok(Some(_))) = user_resource.get() {
            // User is logged in, redirect to home or profile
            window().location().replace("/").unwrap();
        }
    });
    view! {
        <div class="flex justify-center items-center">
            <h2 class="text-gray-100 text-3xl">Welcome, please log in.</h2>
        </div>
    }
}

#[component]
fn UserProfile(user: UserClientInfo) -> impl IntoView {
    view! {
        <h3>"Your Profile"</h3>
        <p>"Name: " {user.name}</p>
        <p>"Email: " {user.email}</p>
        // Display other user info here
    }
}

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <div class="flex justify-center items-center">
            <h2 class="text-gray-100 text-3xl">"404 Not Found"</h2>
        </div>
    }
}

// --- Leptos Server Functions ---

#[server(CheckAuth, "/api")]
pub async fn check_auth() -> Result<Option<UserClientInfo>, ServerFnError> {
    use crate::auth::SESSION_COOKIE_NAME;
    use crate::db::find_user_by_id;
    use crate::db::get_database;
    use axum::extract::FromRequestParts; // Needs to be in scope for extraction
    use leptos_axum::extract;
    use mongodb::Client as MongoClient;
    use tower_cookies::Cookies; // Import CookieManagerLayer for extraction setup
    use tower_cookies::Key;

    // Get Axum parts from Leptos context (requires setup in main.rs)
    let req_parts = extract().await;
    let mut parts = req_parts.unwrap();

    let maybe_key = use_context::<Key>();
    let maybe_db_client = use_context::<MongoClient>();

    if maybe_key.is_none() || maybe_db_client.is_none() {
        // Log error: Context not available
        eprintln!("Error: Key or DB Client context not found in check_auth server fn.");
        return Err(ServerFnError::ServerError(
            "Server configuration error.".to_string(),
        ));
    }
    let key = maybe_key.unwrap();
    let db_client = maybe_db_client.unwrap();
    let db = get_database(&db_client).map_err(|e| ServerFnError::new(e.to_string()))?; // Use ServerFnError::ServerError for config issues

    // Manually extract cookies using the key
    // NOTE: This requires the CookieManagerLayer to be added to the Axum app!
    let cookies = match Cookies::from_request_parts(&mut parts, &key).await {
        Ok(c) => c,
        Err(_) => {
            // This often means the CookieManagerLayer is missing or Key is wrong
            eprintln!(
                "Error: Could not extract cookies in check_auth. Is CookieManagerLayer added?"
            );
            return Ok(None); // Treat as not logged in if cookies can't be parsed
        }
    };

    // Get the session cookie using the private jar
    let private_jar = cookies.private(&key);
    if let Some(cookie) = private_jar.get(SESSION_COOKIE_NAME) {
        let user_id_hex = cookie.value().to_string();
        // Convert hex string back to ObjectId
        if let Ok(oid) = bson::oid::ObjectId::parse_str(&user_id_hex) {
            // Find user in DB
            match find_user_by_id(&db, &oid).await {
                Ok(Some(user)) => Ok(Some((&user).into())), // Convert User to UserClientInfo
                Ok(None) => Ok(None), // User ID in cookie but not in DB (invalid session)
                Err(e) => {
                    eprintln!("DB Error checking auth: {}", e);
                    Err(ServerFnError::ServerError(
                        "Database error during authentication check.".to_string(),
                    ))
                }
            }
        } else {
            Ok(None) // Invalid ObjectId format in cookie
        }
    } else {
        Ok(None) // No session cookie found
    }
}

#[server(Logout, "/api")]
pub async fn logout() -> Result<(), ServerFnError> {
    use crate::auth::{setup_cookie, SESSION_COOKIE_NAME};
    use axum::extract::FromRequestParts; // Needs to be in scope for extraction
    use leptos::logging::log;
    use leptos_axum::extract;
    use tower_cookies::Cookies; // Import CookieManagerLayer for extraction setup
    use tower_cookies::Key;

    // Similar to check_auth, need access to Cookies and Key
    let req_parts = extract().await;
    let mut parts = req_parts.unwrap();

    let maybe_key = use_context::<Key>();
    if maybe_key.is_none() {
        eprintln!("Error: Key context not found in logout server fn.");
        return Err(ServerFnError::ServerError(
            "Server configuration error.".to_string(),
        ));
    }
    let key = maybe_key.unwrap();

    // Manually extract cookies
    let cookies = match Cookies::from_request_parts(&mut parts, &key).await {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Error: Could not extract cookies in logout. Is CookieManagerLayer added?");
            // Even if extraction fails, attempt to set a removal cookie header manually?
            // Or just return Ok assuming the cookie might not exist anyway.
            return Ok(());
        }
    };

    // Remove the session cookie using the private jar
    let private_jar = cookies.private(&key);
    if let Some(mut cookie) = private_jar.get(SESSION_COOKIE_NAME) {
        setup_cookie(&mut cookie);
        log!("Removing cookie: {:?}", cookie);
        private_jar.remove(cookie); // This adds the Set-Cookie header to clear it
    }

    Ok(())
}
