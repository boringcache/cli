use super::*;

pub enum UploadSessionBody {
    OwnedTempFile,
    BorrowedBlobRead { lease: BlobReadLease },
}

pub struct UploadSession {
    pub id: String,
    pub name: String,
    pub temp_path: PathBuf,
    pub body: UploadSessionBody,
    pub write_lock: Arc<Mutex<()>>,
    pub bytes_received: u64,
    pub finalized_digest: Option<String>,
    pub finalized_size: Option<u64>,
    pub created_at: Instant,
}

impl UploadSession {
    pub fn owned_temp_file(
        id: String,
        name: String,
        temp_path: PathBuf,
        bytes_received: u64,
        finalized_digest: Option<String>,
        finalized_size: Option<u64>,
    ) -> Self {
        Self {
            id,
            name,
            temp_path,
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(Mutex::new(())),
            bytes_received,
            finalized_digest,
            finalized_size,
            created_at: Instant::now(),
        }
    }

    pub fn borrowed_blob_read(
        id: String,
        name: String,
        digest: String,
        size_bytes: u64,
        lease: BlobReadLease,
    ) -> Self {
        let temp_path = lease.path().to_path_buf();
        Self {
            id,
            name,
            temp_path,
            body: UploadSessionBody::BorrowedBlobRead { lease },
            write_lock: Arc::new(Mutex::new(())),
            bytes_received: size_bytes,
            finalized_digest: Some(digest),
            finalized_size: Some(size_bytes),
            created_at: Instant::now(),
        }
    }

    pub fn body_path(&self) -> &Path {
        match &self.body {
            UploadSessionBody::OwnedTempFile => self.temp_path.as_path(),
            UploadSessionBody::BorrowedBlobRead { lease } => lease.path(),
        }
    }

    pub fn body_offset(&self) -> u64 {
        match &self.body {
            UploadSessionBody::OwnedTempFile => 0,
            UploadSessionBody::BorrowedBlobRead { lease } => lease.offset(),
        }
    }

    pub fn body_size(&self) -> u64 {
        match &self.body {
            UploadSessionBody::OwnedTempFile => self.finalized_size.unwrap_or(self.bytes_received),
            UploadSessionBody::BorrowedBlobRead { lease } => lease.size_bytes(),
        }
    }

    pub fn owns_temp_file(&self) -> bool {
        matches!(self.body, UploadSessionBody::OwnedTempFile)
    }
}

#[derive(Default)]
pub struct UploadSessionStore {
    sessions: HashMap<String, UploadSession>,
}

impl UploadSessionStore {
    pub fn create(&mut self, session: UploadSession) {
        self.sessions.insert(session.id.clone(), session);
    }

    pub fn get(&self, id: &str) -> Option<&UploadSession> {
        self.sessions.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut UploadSession> {
        self.sessions.get_mut(id)
    }

    pub fn remove(&mut self, id: &str) -> Option<UploadSession> {
        self.sessions.remove(id)
    }

    pub fn cleanup_expired(&mut self, max_age: std::time::Duration) -> Vec<UploadSession> {
        let now = Instant::now();
        let expired_keys: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.duration_since(s.created_at) >= max_age)
            .map(|(k, _)| k.clone())
            .collect();
        expired_keys
            .iter()
            .filter_map(|k| self.sessions.remove(k))
            .collect()
    }

    pub fn find_by_digest(&self, digest: &str) -> Option<&UploadSession> {
        self.sessions
            .values()
            .filter(|s| s.finalized_digest.as_deref() == Some(digest))
            .max_by_key(|s| s.finalized_size.unwrap_or(s.bytes_received))
    }

    pub fn find_by_name_and_digest(&self, name: &str, digest: &str) -> Option<&UploadSession> {
        self.sessions
            .values()
            .filter(|s| s.name == name && s.finalized_digest.as_deref() == Some(digest))
            .max_by_key(|s| s.finalized_size.unwrap_or(s.bytes_received))
    }
}
