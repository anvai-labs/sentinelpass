//! Repository pattern for data access abstraction.
//!
//! This module provides traits and implementations for database operations,
//! decoupling the vault layer from direct SQLite access.
//!
//! The repository works with raw database rows (encrypted BLOBs).
//! The vault layer is responsible for encryption/decryption.

use crate::database::schema::Database;
use crate::DatabaseError;
use rusqlite::{OptionalExtension, Row};

/// Filter options for listing entries
#[derive(Debug, Clone, Default)]
pub struct EntryFilter {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub favorite_only: bool,
}

/// Raw encrypted entry row from the database
#[derive(Debug, Clone)]
pub struct RawEntryRow {
    pub entry_id: i64,
    pub title: Vec<u8>,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub url: Option<Vec<u8>>,
    pub notes: Option<Vec<u8>>,
    pub credential_type: String,
    pub entry_nonce: Vec<u8>,
    pub auth_tag: Vec<u8>,
    pub created_at: i64,
    pub modified_at: i64,
    pub favorite: bool,
    pub sync_id: Option<String>,
    pub sync_version: i64,
}

/// Parameters for creating a new entry
pub struct NewEntryParams {
    pub title: Vec<u8>,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub url: Option<Vec<u8>>,
    pub notes: Option<Vec<u8>>,
    pub credential_type: String,
    pub entry_nonce: Vec<u8>,
    pub auth_tag: Vec<u8>,
    pub created_at: i64,
    pub modified_at: i64,
    pub favorite: bool,
    pub sync_id: Option<String>,
}

/// Parameters for updating an existing entry
pub struct UpdateEntryParams {
    pub title: Option<Vec<u8>>,
    pub username: Option<Vec<u8>>,
    pub password: Option<Vec<u8>>,
    pub url: Option<Vec<u8>>,
    pub notes: Option<Vec<u8>>,
    pub credential_type: Option<String>,
    pub entry_nonce: Option<Vec<u8>>,
    pub auth_tag: Option<Vec<u8>>,
    pub modified_at: i64,
    pub favorite: Option<bool>,
}

/// Repository trait for entry CRUD operations
pub trait EntryRepository {
    /// Create a new entry and return its ID
    fn create(&self, entry: NewEntryParams) -> Result<i64, DatabaseError>;

    /// Get a raw entry row by ID (encrypted)
    fn get_raw(&self, id: i64) -> Result<Option<RawEntryRow>, DatabaseError>;

    /// List raw entry rows with optional filtering
    fn list_raw(&self, filter: EntryFilter) -> Result<Vec<RawEntryRow>, DatabaseError>;

    /// Update an existing entry
    fn update(&self, id: i64, entry: UpdateEntryParams) -> Result<(), DatabaseError>;

    /// Delete an entry by ID
    fn delete(&self, id: i64) -> Result<(), DatabaseError>;

    /// Count total entries
    fn count(&self) -> Result<i64, DatabaseError>;

    /// Check if an entry exists
    fn exists(&self, id: i64) -> Result<bool, DatabaseError>;

    /// Find entries by domain using the domain_mappings index
    fn find_by_domain(&self, domain: &str) -> Result<Vec<RawEntryRow>, DatabaseError>;
}

/// SQLite implementation of EntryRepository
pub struct SqliteEntryRepository<'a> {
    db: &'a Database,
}

impl<'a> SqliteEntryRepository<'a> {
    /// Create a new SQLite-backed entry repository
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    fn parse_row(row: &Row) -> rusqlite::Result<RawEntryRow> {
        Ok(RawEntryRow {
            entry_id: row.get(0)?,
            title: row.get(1)?,
            username: row.get(2)?,
            password: row.get(3)?,
            url: row.get(4)?,
            notes: row.get(5)?,
            credential_type: row.get(6)?,
            entry_nonce: row.get(7)?,
            auth_tag: row.get(8)?,
            created_at: row.get(9)?,
            modified_at: row.get(10)?,
            favorite: row.get::<_, i32>(11)? == 1,
            sync_id: row.get(12)?,
            sync_version: row.get(13)?,
        })
    }
}

impl<'a> EntryRepository for SqliteEntryRepository<'a> {
    fn create(&self, entry: NewEntryParams) -> Result<i64, DatabaseError> {
        let conn = self.db.conn();

        conn.execute(
            "INSERT INTO entries (
                vault_id, title, username, password, url, notes, credential_type,
                entry_nonce, auth_tag, created_at, modified_at, favorite,
                sync_id, sync_version, sync_state
            ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, 'pending')",
            rusqlite::params![
                entry.title,
                entry.username,
                entry.password,
                entry.url,
                entry.notes,
                entry.credential_type,
                entry.entry_nonce,
                entry.auth_tag,
                entry.created_at,
                entry.modified_at,
                entry.favorite,
                entry.sync_id,
            ],
        )
        .map_err(DatabaseError::Sqlite)?;

        Ok(conn.last_insert_rowid())
    }

    fn get_raw(&self, id: i64) -> Result<Option<RawEntryRow>, DatabaseError> {
        let conn = self.db.conn();

        let mut stmt = conn
            .prepare(
                "SELECT entry_id, title, username, password, url, notes, credential_type,
                 entry_nonce, auth_tag, created_at, modified_at, favorite,
                 sync_id, sync_version
                 FROM entries WHERE entry_id = ?1 AND is_deleted = 0",
            )
            .map_err(DatabaseError::Sqlite)?;

        let result = stmt
            .query_row(rusqlite::params![id], Self::parse_row)
            .optional()
            .map_err(DatabaseError::Sqlite)?;

        Ok(result)
    }

    fn list_raw(&self, filter: EntryFilter) -> Result<Vec<RawEntryRow>, DatabaseError> {
        let conn = self.db.conn();

        let mut query = String::from(
            "SELECT entry_id, title, username, password, url, notes, credential_type,
             entry_nonce, auth_tag, created_at, modified_at, favorite,
             sync_id, sync_version
             FROM entries WHERE is_deleted = 0",
        );

        if filter.favorite_only {
            query.push_str(" AND favorite = 1");
        }

        query.push_str(" ORDER BY entry_id ASC");

        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_index = 1;

        if let Some(limit) = filter.limit {
            query.push_str(&format!(" LIMIT ?{}", param_index));
            params.push(Box::new(limit));
            param_index += 1;
        }
        if let Some(offset) = filter.offset {
            query.push_str(&format!(" OFFSET ?{}", param_index));
            params.push(Box::new(offset));
            let _ = param_index; // suppress unused warning
        }

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&query).map_err(DatabaseError::Sqlite)?;

        let rows = stmt
            .query_map(param_refs.as_slice(), Self::parse_row)
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?;

        Ok(rows)
    }

    fn update(&self, id: i64, entry: UpdateEntryParams) -> Result<(), DatabaseError> {
        let conn = self.db.conn();

        let mut set_clauses = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_index = 1;

        if entry.title.is_some() {
            set_clauses.push(format!("title = ?{}", param_index));
            param_index += 1;
        }
        if entry.username.is_some() {
            set_clauses.push(format!("username = ?{}", param_index));
            param_index += 1;
        }
        if entry.password.is_some() {
            set_clauses.push(format!("password = ?{}", param_index));
            param_index += 1;
        }
        if entry.url.is_some() {
            set_clauses.push(format!("url = ?{}", param_index));
            param_index += 1;
        }
        if entry.notes.is_some() {
            set_clauses.push(format!("notes = ?{}", param_index));
            param_index += 1;
        }
        if entry.credential_type.is_some() {
            set_clauses.push(format!("credential_type = ?{}", param_index));
            param_index += 1;
        }
        if entry.entry_nonce.is_some() {
            set_clauses.push(format!("entry_nonce = ?{}", param_index));
            param_index += 1;
        }
        if entry.auth_tag.is_some() {
            set_clauses.push(format!("auth_tag = ?{}", param_index));
            param_index += 1;
        }
        if entry.favorite.is_some() {
            set_clauses.push(format!("favorite = ?{}", param_index));
            param_index += 1;
        }

        set_clauses.push(format!("modified_at = ?{}", param_index));
        param_index += 1;

        // Always increment sync_version on update
        set_clauses.push("sync_version = sync_version + 1".to_string());
        set_clauses.push("sync_state = 'pending'".to_string());

        let query = format!(
            "UPDATE entries SET {} WHERE entry_id = ?{}",
            set_clauses.join(", "),
            param_index
        );

        // Build params in the correct order using Box to own the values
        if let Some(v) = entry.title {
            params.push(Box::new(v));
        }
        if let Some(v) = entry.username {
            params.push(Box::new(v));
        }
        if let Some(v) = entry.password {
            params.push(Box::new(v));
        }
        if let Some(v) = entry.url {
            params.push(Box::new(v));
        }
        if let Some(v) = entry.notes {
            params.push(Box::new(v));
        }
        if let Some(v) = entry.credential_type {
            params.push(Box::new(v));
        }
        if let Some(v) = entry.entry_nonce {
            params.push(Box::new(v));
        }
        if let Some(v) = entry.auth_tag {
            params.push(Box::new(v));
        }
        if let Some(v) = entry.favorite {
            params.push(Box::new(if v { 1i32 } else { 0 }));
        }
        params.push(Box::new(entry.modified_at));
        params.push(Box::new(id));

        // Convert Box<dyn ToSql> to &dyn ToSql
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        conn.execute(&query, param_refs.as_slice())
            .map_err(DatabaseError::Sqlite)?;

        Ok(())
    }

    fn delete(&self, id: i64) -> Result<(), DatabaseError> {
        let conn = self.db.conn();

        conn.execute("DELETE FROM entries WHERE entry_id = ?1", [id])
            .map_err(DatabaseError::Sqlite)?;

        Ok(())
    }

    fn count(&self) -> Result<i64, DatabaseError> {
        let conn = self.db.conn();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE is_deleted = 0",
                [],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;

        Ok(count)
    }

    fn exists(&self, id: i64) -> Result<bool, DatabaseError> {
        let conn = self.db.conn();

        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM entries WHERE entry_id = ?1 AND is_deleted = 0)",
                [id],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;

        Ok(exists)
    }

    fn find_by_domain(&self, domain: &str) -> Result<Vec<RawEntryRow>, DatabaseError> {
        let conn = self.db.conn();

        let mut stmt = conn
            .prepare(
                "SELECT e.entry_id, e.title, e.username, e.password, e.url, e.notes, e.credential_type,
                 e.entry_nonce, e.auth_tag, e.created_at, e.modified_at, e.favorite,
                 e.sync_id, e.sync_version
                 FROM entries e
                 JOIN domain_mappings dm ON dm.entry_id = e.entry_id
                 WHERE dm.domain = ?1 AND e.is_deleted = 0",
            )
            .map_err(DatabaseError::Sqlite)?;

        let rows = stmt
            .query_map(rusqlite::params![domain], Self::parse_row)
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_in_memory_db() -> Database {
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        db
    }

    #[test]
    fn test_repository_create_entry() {
        let db = create_in_memory_db();
        let repo = SqliteEntryRepository::new(&db);

        let new_entry = NewEntryParams {
            title: b"Test Entry".to_vec(),
            username: b"user@example.com".to_vec(),
            password: b"password123".to_vec(),
            url: Some(b"https://example.com".to_vec()),
            notes: None,
            credential_type: "password".to_string(),
            entry_nonce: vec![0u8; 12],
            auth_tag: vec![0u8; 16],
            created_at: Utc::now().timestamp(),
            modified_at: Utc::now().timestamp(),
            favorite: false,
            sync_id: None,
        };

        let entry_id = repo.create(new_entry).unwrap();
        assert!(entry_id > 0);
    }

    #[test]
    fn test_repository_get_entry() {
        let db = create_in_memory_db();
        let repo = SqliteEntryRepository::new(&db);

        let new_entry = NewEntryParams {
            title: b"Test Entry".to_vec(),
            username: b"user@example.com".to_vec(),
            password: b"password123".to_vec(),
            url: Some(b"https://example.com".to_vec()),
            notes: None,
            credential_type: "api_key".to_string(),
            entry_nonce: vec![0u8; 12],
            auth_tag: vec![0u8; 16],
            created_at: Utc::now().timestamp(),
            modified_at: Utc::now().timestamp(),
            favorite: false,
            sync_id: None,
        };

        let entry_id = repo.create(new_entry).unwrap();
        let retrieved = repo.get_raw(entry_id).unwrap();

        assert!(retrieved.is_some());
        let row = retrieved.unwrap();
        assert_eq!(row.entry_id, entry_id);
        assert_eq!(row.title, b"Test Entry");
        assert_eq!(row.username, b"user@example.com");
        assert_eq!(row.credential_type, "api_key");
    }

    #[test]
    fn test_repository_list_entries() {
        let db = create_in_memory_db();
        let repo = SqliteEntryRepository::new(&db);

        // Create multiple entries
        for i in 0..5 {
            let new_entry = NewEntryParams {
                title: format!("Entry {}", i).as_bytes().to_vec(),
                username: b"user@example.com".to_vec(),
                password: b"password123".to_vec(),
                url: None,
                notes: None,
                credential_type: "password".to_string(),
                entry_nonce: vec![0u8; 12],
                auth_tag: vec![0u8; 16],
                created_at: Utc::now().timestamp(),
                modified_at: Utc::now().timestamp(),
                favorite: false,
                sync_id: None,
            };
            repo.create(new_entry).unwrap();
        }

        let filter = EntryFilter::default();
        let entries = repo.list_raw(filter).unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn test_repository_count() {
        let db = create_in_memory_db();
        let repo = SqliteEntryRepository::new(&db);

        assert_eq!(repo.count().unwrap(), 0);

        let new_entry = NewEntryParams {
            title: b"Test Entry".to_vec(),
            username: b"user@example.com".to_vec(),
            password: b"password123".to_vec(),
            url: None,
            notes: None,
            credential_type: "password".to_string(),
            entry_nonce: vec![0u8; 12],
            auth_tag: vec![0u8; 16],
            created_at: Utc::now().timestamp(),
            modified_at: Utc::now().timestamp(),
            favorite: false,
            sync_id: None,
        };

        repo.create(new_entry).unwrap();
        assert_eq!(repo.count().unwrap(), 1);
    }

    #[test]
    fn test_repository_delete_entry() {
        let db = create_in_memory_db();
        let repo = SqliteEntryRepository::new(&db);

        let new_entry = NewEntryParams {
            title: b"Test Entry".to_vec(),
            username: b"user@example.com".to_vec(),
            password: b"password123".to_vec(),
            url: None,
            notes: None,
            credential_type: "password".to_string(),
            entry_nonce: vec![0u8; 12],
            auth_tag: vec![0u8; 16],
            created_at: Utc::now().timestamp(),
            modified_at: Utc::now().timestamp(),
            favorite: false,
            sync_id: None,
        };

        let entry_id = repo.create(new_entry).unwrap();
        assert!(repo.get_raw(entry_id).unwrap().is_some());

        repo.delete(entry_id).unwrap();
        assert!(repo.get_raw(entry_id).unwrap().is_none());
    }

    #[test]
    fn test_repository_exists() {
        let db = create_in_memory_db();
        let repo = SqliteEntryRepository::new(&db);

        assert!(!repo.exists(1).unwrap());

        let new_entry = NewEntryParams {
            title: b"Test Entry".to_vec(),
            username: b"user@example.com".to_vec(),
            password: b"password123".to_vec(),
            url: None,
            notes: None,
            credential_type: "password".to_string(),
            entry_nonce: vec![0u8; 12],
            auth_tag: vec![0u8; 16],
            created_at: Utc::now().timestamp(),
            modified_at: Utc::now().timestamp(),
            favorite: false,
            sync_id: None,
        };

        let entry_id = repo.create(new_entry).unwrap();
        assert!(repo.exists(entry_id).unwrap());
        assert!(!repo.exists(999).unwrap());
    }

    #[test]
    fn test_repository_find_by_domain() {
        let db = create_in_memory_db();
        let repo = SqliteEntryRepository::new(&db);

        // Create an entry
        let new_entry = NewEntryParams {
            title: b"Test Entry".to_vec(),
            username: b"user@example.com".to_vec(),
            password: b"password123".to_vec(),
            url: Some(b"https://example.com".to_vec()),
            notes: None,
            credential_type: "password".to_string(),
            entry_nonce: vec![0u8; 12],
            auth_tag: vec![0u8; 16],
            created_at: Utc::now().timestamp(),
            modified_at: Utc::now().timestamp(),
            favorite: false,
            sync_id: None,
        };
        let entry_id = repo.create(new_entry).unwrap();

        // Insert a domain mapping for this entry
        db.conn()
            .execute(
                "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, ?2, 1)",
                rusqlite::params![entry_id, "example.com"],
            )
            .unwrap();

        // Find by domain should return the entry
        let results = repo.find_by_domain("example.com").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, entry_id);

        // Non-matching domain returns empty
        let results = repo.find_by_domain("other.com").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_repository_filter_by_favorite() {
        let db = create_in_memory_db();
        let repo = SqliteEntryRepository::new(&db);

        // Create a favorite entry
        let fav_entry = NewEntryParams {
            title: b"Favorite Entry".to_vec(),
            username: b"user@example.com".to_vec(),
            password: b"password123".to_vec(),
            url: None,
            notes: None,
            credential_type: "password".to_string(),
            entry_nonce: vec![0u8; 12],
            auth_tag: vec![0u8; 16],
            created_at: Utc::now().timestamp(),
            modified_at: Utc::now().timestamp(),
            favorite: true,
            sync_id: None,
        };
        repo.create(fav_entry).unwrap();

        // Create a non-favorite entry
        let reg_entry = NewEntryParams {
            title: b"Regular Entry".to_vec(),
            username: b"user@example.com".to_vec(),
            password: b"password123".to_vec(),
            url: None,
            notes: None,
            credential_type: "password".to_string(),
            entry_nonce: vec![0u8; 12],
            auth_tag: vec![0u8; 16],
            created_at: Utc::now().timestamp(),
            modified_at: Utc::now().timestamp(),
            favorite: false,
            sync_id: None,
        };
        repo.create(reg_entry).unwrap();

        let filter = EntryFilter {
            favorite_only: true,
            ..Default::default()
        };
        let entries = repo.list_raw(filter).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].favorite);
    }

    #[test]
    fn test_repository_with_limit_and_offset() {
        let db = create_in_memory_db();
        let repo = SqliteEntryRepository::new(&db);

        // Create 10 entries
        for i in 0..10 {
            let new_entry = NewEntryParams {
                title: format!("Entry {}", i).as_bytes().to_vec(),
                username: b"user@example.com".to_vec(),
                password: b"password123".to_vec(),
                url: None,
                notes: None,
                credential_type: "password".to_string(),
                entry_nonce: vec![0u8; 12],
                auth_tag: vec![0u8; 16],
                created_at: Utc::now().timestamp(),
                modified_at: Utc::now().timestamp(),
                favorite: false,
                sync_id: None,
            };
            repo.create(new_entry).unwrap();
        }

        // Get first page
        let filter = EntryFilter {
            limit: Some(5),
            offset: Some(0),
            ..Default::default()
        };
        let entries = repo.list_raw(filter).unwrap();
        assert_eq!(entries.len(), 5);

        // Get second page
        let filter = EntryFilter {
            limit: Some(5),
            offset: Some(5),
            ..Default::default()
        };
        let entries = repo.list_raw(filter).unwrap();
        assert_eq!(entries.len(), 5);
    }
}
