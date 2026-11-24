pub mod product_tags;

use std::collections::HashMap;
use std::time::Instant;

use axum::extract::{Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use sqlx::any::{install_default_drivers, AnyPoolOptions};
use sqlx::{AnyPool, Executor};

use crate::product_tags::{read_product_tags, ProductTagsRequest};

/// Opens a pool whose every connection refuses writes, as a second guard next to the read-only login.
pub async fn connect_read_only(database_url: &str) -> Result<AnyPool, sqlx::Error> {
    install_default_drivers();
    AnyPoolOptions::new()
        .after_connect(|connection, _| {
            Box::pin(async move {
                let statement = match connection.backend_name() {
                    "PostgreSQL" => "SET default_transaction_read_only = on",
                    "SQLite" => "PRAGMA query_only = ON",
                    other => return Err(sqlx::Error::Configuration(format!("unsupported database backend {other}").into())),
                };
                connection.execute(statement).await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
}

pub fn router(pool: AnyPool) -> Router {
    Router::new()
        .route("/api/catalog/product-tags", get(product_tags))
        .layer(middleware::from_fn(log_request))
        .with_state(pool)
}

#[derive(Clone, Copy)]
struct ItemCount(usize);

async fn product_tags(State(pool): State<AnyPool>, Query(params): Query<HashMap<String, String>>) -> Response {
    let request = match ProductTagsRequest::from_query(&params) {
        Ok(request) => request,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    match read_product_tags(&pool, &request).await {
        Ok(items) => {
            let count = ItemCount(items.len());
            let mut response = Json(items).into_response();
            response.extensions_mut().insert(count);
            response
        }
        Err(error) => {
            eprintln!("product tags read failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn log_request(request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let response = next.run(request).await;
    let items = response
        .extensions()
        .get::<ItemCount>()
        .map_or_else(|| "-".to_string(), |count| count.0.to_string());
    println!(
        "{method} {uri} status={} items={items} elapsed_ms={}",
        response.status().as_u16(),
        started.elapsed().as_millis()
    );
    response
}
