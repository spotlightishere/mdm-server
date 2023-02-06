use diesel::{
    r2d2::{Builder, ConnectionManager, Pool, PooledConnection},
    sqlite::SqliteConnection,
};
use std::time::Duration;

type DbConnection = ConnectionManager<SqliteConnection>;

#[derive(Clone)]
pub struct Database {
    internal_pool: Pool<DbConnection>,
}

// Simple axum extension permitting for pooling of SQLite3 connections.
impl Database {
    /// Opens the pool against the specified SQLite3 database.
    pub fn open(db_path: &String) -> Self {
        let manager = ConnectionManager::<SqliteConnection>::new(db_path);
        let pool = Builder::new()
            .connection_timeout(Duration::from_secs(5))
            .build(manager)
            .expect("unable to create database pool");

        Database {
            internal_pool: pool,
        }
    }

    /// Begins a new connection.
    /// There's no need to worry about manually closing
    /// and returning to the pool, as this will occur automatically.
    pub fn connection(&self) -> PooledConnection<DbConnection> {
        self.internal_pool.get().unwrap()
    }
}
