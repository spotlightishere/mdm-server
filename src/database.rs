use crate::config::Config;
use axum::Extension;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Clone)]
pub struct Database {
    internal_pool: Pool<SqliteConnectionManager>,
}

// Simple axum extension permitting for pooling of SQLite3 connections.
impl Database {
    /// Opens the pool against the specified SQLite3 database.
    pub fn open() -> Result<Extension<Database>, r2d2::Error> {
        let database_path = Path::new(&Config::storage().database_path);
        Self::attempt_create_parents(database_path);
        let manager = SqliteConnectionManager::file(database_path);
        let pool = r2d2::Builder::new()
            .connection_timeout(Duration::from_secs(5))
            .build(manager)?;
        Ok(Extension(Database {
            internal_pool: pool,
        }))
    }

    /// Creates parent directories for our SQLite3 database if they do not already exist.
    fn attempt_create_parents(database_path: &Path) {
        // Check to see if we need to do anything.
        if database_path.exists() {
            return;
        }

        // Create parent directories, if necessary.
        let parents = database_path.parent().unwrap();
        fs::create_dir_all(parents)
            .expect("should be able to create parent directories for database")
    }

    /// Begins a new connection.
    /// There's no need to worry about manually closing
    /// and returning to the pool, as this will occur automatically.
    pub fn connection(&self) -> PooledConnection<SqliteConnectionManager> {
        self.internal_pool.get().unwrap()
    }
}
