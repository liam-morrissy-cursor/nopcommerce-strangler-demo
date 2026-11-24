use std::env;
use std::error::Error;

use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let database_url = env::var("CATALOG_READS_DATABASE_URL").map_err(|_| "CATALOG_READS_DATABASE_URL is required")?;
    let listen = env::var("CATALOG_READS_LISTEN").unwrap_or_else(|_| "127.0.0.1:5080".to_string());

    let pool = catalog_reads::connect_read_only(&database_url).await?;
    let listener = TcpListener::bind(&listen).await?;
    println!("catalog-reads listening on {}", listener.local_addr()?);

    axum::serve(listener, catalog_reads::router(pool)).await?;
    Ok(())
}
