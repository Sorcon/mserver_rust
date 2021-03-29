use derive_more::{Display, Error};
use actix_web::{HttpResponse, dev::HttpResponseBuilder, error, http::{StatusCode, header}};
#[derive(Debug, Display, Error)]
pub enum MServerError {
    #[display(fmt = "internal error")]
    InternalError,

    #[display(fmt = "bad request")]
    BadClientData,

    #[display(fmt = "timeout")]
    Timeout,
}

impl error::ResponseError for MServerError {
    fn error_response(&self) -> HttpResponse {
        HttpResponseBuilder::new(self.status_code())
            .set_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            MServerError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            MServerError::BadClientData => StatusCode::BAD_REQUEST,
            MServerError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}