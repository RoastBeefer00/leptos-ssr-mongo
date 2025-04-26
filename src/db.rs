use crate::models::User;
use leptos::prelude::ServerFnError;
use mongodb::{bson::doc, options::ClientOptions, Client as MongoClient, Collection, Database};
use std::env;

/// Initializes the MongoDB client. Call this once at server startup.
pub async fn connect_db() -> Result<MongoClient, ServerFnError> {
    let db_uri =
        env::var("DATABASE_URL").map_err(|_| ServerFnError::new("DATABASE_URL".to_string()))?;
    let client_options = ClientOptions::parse(&db_uri)
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to parse DB URI: {}", e)))?;
    let client = MongoClient::with_options(client_options)
        .map_err(|e| ServerFnError::new(format!("Failed to create DB client: {}", e)))?;
    // Ping the server to ensure connection before proceeding
    client
        .database("admin") // Or use the configured DB name
        .run_command(doc! { "ping": 1 }, None)
        .await
        .map_err(|e| ServerFnError::new(format!("DB Ping failed: {}", e)))?;
    println!("MongoDB connected successfully.");
    Ok(client)
}

/// Gets the specific database instance from the client.
pub fn get_database(client: &MongoClient) -> Result<Database, ServerFnError> {
    let db_name =
        env::var("DATABASE_NAME").map_err(|_| ServerFnError::new("DATABASE_NAME".to_string()))?;
    Ok(client.database(&db_name))
}

/// Gets the 'users' collection.
fn get_users_collection(db: &Database) -> Collection<User> {
    db.collection::<User>("users")
}

/// Finds a user by their Google ID or creates a new one if not found.
pub async fn find_or_create_user(
    db: &Database,
    google_id: &str,
    email: &str,
    name: &str,
) -> Result<User, ServerFnError> {
    let users_collection = get_users_collection(db);

    let filter = doc! { "google_id": google_id };
    if let Some(mut user) = users_collection.find_one(filter.clone(), None).await? {
        // Optionally update user info if changed (e.g., name)
        if user.email != email || user.name != name {
            user.email = email.to_string();
            user.name = name.to_string();
            let update = doc! { "$set": { "email": email, "name": name } };
            users_collection.update_one(filter, update, None).await?;
        }
        Ok(user)
    } else {
        // User not found, create a new one
        let new_user = User {
            id: None, // MongoDB will generate the _id
            google_id: google_id.to_string(),
            email: email.to_string(),
            name: name.to_string(),
        };
        let insert_result = users_collection.insert_one(&new_user, None).await?;
        // Fetch the newly created user to get the generated ID
        let created_user = users_collection
            .find_one(doc! { "_id": insert_result.inserted_id }, None)
            .await?
            .ok_or_else(|| {
                ServerFnError::new("Failed to retrieve newly created user".to_string())
            })?;
        Ok(created_user)
    }
}

/// Finds a user by their internal MongoDB ObjectId.
pub async fn find_user_by_id(
    db: &Database,
    user_id: &bson::oid::ObjectId,
) -> Result<Option<User>, ServerFnError> {
    let users_collection = get_users_collection(db);
    let filter = doc! { "_id": user_id };
    Ok(users_collection.find_one(filter, None).await?)
}
