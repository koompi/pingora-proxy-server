use axum::{
    extract::State,
    response::Json,
    routing::{delete, post},
};
use serde::Deserialize;

#[derive(Deserialize)]
struct CertificateRequest {
    cert_path: String,
    key_path: String,
}

async fn add_certificate(
    State(state): State<AppState>,
    Json(req): Json<CertificateRequest>,
) -> Result<Json<()>, StatusCode> {
    match state
        .certificates
        .add_certificate(&req.cert_path, &req.key_path)
    {
        Ok(_) => Ok(Json(())),
        Err(e) => {
            log::error!("Failed to add certificate: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn remove_certificate(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<()>, StatusCode> {
    match state.certificates.remove_certificate(&domain) {
        Ok(_) => Ok(Json(())),
        Err(e) => {
            log::error!("Failed to remove certificate: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
