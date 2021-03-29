use actix_web::dev::ServiceRequest;
use actix_web::middleware::Logger;
use actix_web::*;

use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::middleware::HttpAuthentication;

use actix_web_grants::proc_macro::{has_any_role, has_permissions};
// Used for integration with `actix-web-httpauth`
use actix_web_grants::permissions::AttachPermissions;

use crate::auth::claims::Claims;
use crate::utils::merror::MServerError;
use crate::models::user::{User, UserRole, init_user};
use env_logger;
use serde_derive::{Deserialize, Serialize};
mod auth;
mod utils;
mod models;

#[get("/admin")]
#[has_permissions("OP_GET_SECURED_INFO")]
async fn permission_secured() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[get("/manager")]
#[has_any_role("ADMIN", "MANAGER")]
async fn manager_secured() -> HttpResponse {
    HttpResponse::Ok().finish()
}

async fn validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, Error> {
    // We just get permissions from JWT
    let claims = auth::claims::decode_jwt(credentials.token())?;
    req.attach(claims.permissions);
    Ok(req)
}

#[post("/token")]
pub async fn create_token(
    info: web::Json<UserPermissionsRequest>,
) -> Result<web::Json<TokenContainer>, MServerError> {
    let user_info = info.into_inner();
    let old_user: User = User::find_by_name(user_info.username.as_str()).await;
    if user_info.password == old_user.md5password {
        let claims = Claims::new(user_info.username, user_info.permissions);
        let jwt = auth::claims::create_jwt(claims).unwrap();
        Ok(web::Json(TokenContainer { token: jwt }))
    } else {
        Err(MServerError::BadClientData)
    }
}

#[derive(Deserialize)]
pub struct UserPermissionsRequest {
    pub username: String,
    pub permissions: Vec<String>,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenContainer {
    token: String,
}





#[get("/user")]
async fn user() -> Result<web::Json<User>> {
    Ok(web::Json(
        init_user("Sorcon", "test@test.test", "test", UserRole::User)
            .await
            .unwrap(),
    ))
}

#[post("/user")]
async fn set_user(new_user: web::Json<User>) -> Result<web::Json<User>> {
    Ok(new_user)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    HttpServer::new(|| {
        let auth = HttpAuthentication::bearer(validator);
        App::new()
            .service(create_token)
            .service(web::scope("api").wrap(auth).service(user).service(set_user))
            .wrap(Logger::default())
    })
    .bind("192.168.20.122:8080")?
    .run()
    .await
}
