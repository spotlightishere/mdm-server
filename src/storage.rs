use crate::Config;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

impl Config {
    pub fn create_storage_dirs(&self) {
        // First, let's attempt to create our database path.
        // We only need to create its parent storage directories,
        // as SQLite3 will otherwise manage that for us.
        let storage = &self.storage;
        let database_path = Path::new(&storage.database_path);
        if database_path.exists() == false {
            // Create parent directories, if necessary.
            let parents = database_path.parent().unwrap();
            fs::create_dir_all(parents)
                .expect("should be able to create parent directories for database")
        }

        // Next, let's ensure certificates exist.
        let certificates_dir = Path::new(&storage.certificates_dir);
        fs::create_dir_all(certificates_dir)
            .expect("should be able to create parent directories for certificates");

        // Lastly, assets.
        let assets_dir = Path::new(&storage.assets_dir);
        fs::create_dir_all(assets_dir)
            .expect("should be able to create parent directories for assets");
    }

    pub fn certificate_path(&self, filename: &'static str) -> PathBuf {
        Path::new(&self.storage.certificates_dir).join(filename)
    }
}
