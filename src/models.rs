use crate::UserClientInfo;
use bson::oid::ObjectId;
use serde::{Deserialize, Serialize}; // Import ObjectId

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")] // Standard MongoDB ID field
    pub id: Option<ObjectId>,
    pub google_id: String,
    pub email: String,
    pub name: String,
    // Add other fields as needed (e.g., picture_url, created_at)
}

impl From<&User> for UserClientInfo {
    fn from(user: &User) -> Self {
        UserClientInfo {
            email: user.email.clone(),
            name: user.name.clone(),
        }
    }
}

// Structure to hold user info from Google
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GoogleUserInfo {
    pub sub: String, // Google's unique ID for the user
    pub email: String,
    #[serde(default)] // Handle cases where name might be missing
    pub name: String,
    #[serde(default)]
    pub picture: String,
    // Add other fields if needed (e.g., given_name, family_name)
}
