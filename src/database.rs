use axum::Extension;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

use crate::config::Config;

#[derive(Clone)]
pub struct Database {
    internal_pool: Pool<SqliteConnectionManager>,
}

// Simple axum extension permitting for pooling of SQLite3 connections.
impl Database {
    /// Opens the pool against the specified SQLite3 database.
    pub fn open() -> Result<Extension<Database>, r2d2::Error> {
        let database_path = &Config::storage().database_path;
        let manager = SqliteConnectionManager::file(database_path);
        let pool = r2d2::Pool::new(manager)?;
        Ok(Extension(Database {
            internal_pool: pool,
        }))
    }

    /// Begins a new connection.
    /// There's no need to worry about manually closing
    /// and returning to the pool, as this will occur automatically.
    pub fn connection(&self) -> PooledConnection<SqliteConnectionManager> {
        self.internal_pool.get().unwrap()
    }
}
