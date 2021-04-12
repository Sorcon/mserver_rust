use actix_web::Error;
use serde_derive::{Deserialize, Serialize};



#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: Option<i64>,
    pub login: String,
    pub email: String,
    pub role: UserRole,
    pub md5password: String,
}

#[derive(Deserialize)]
pub struct UserPermissionsRequest {
    pub username: String,
    pub permissions: Vec<String>,
    pub password: String,
}

impl User {
    pub async fn find_by_name(name: &str) -> User {
        init_user(name.into(), "email", "password", UserRole::User).await.unwrap()
    }
}

pub async fn init_user(
    login: &str,
    email: &str,
    password: &str,
    role: UserRole,
) -> Result<User, Error> {
    let new_user = User {
        id: None,
        login: login.to_string(),
        email: email.to_string(),
        md5password: password.to_string(),
        role: role,
    }; //add md5, UUID
    Ok(new_user)
}


#[derive(Serialize, Deserialize)]
pub enum UserRole {
    NotAuthorized,
    User,
    Admin,
}
