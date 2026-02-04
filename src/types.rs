use anyhow::Result as AnyhowResult;

pub type Result<T> = AnyhowResult<T>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub fn bytes(&self) -> u64 {
        self.0
    }

    pub fn as_mb(&self) -> f64 {
        self.0 as f64 / (1024.0 * 1024.0)
    }

    pub fn as_gb(&self) -> f64 {
        self.0 as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}

impl std::fmt::Display for ByteSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0;
        if bytes < 1024 {
            write!(f, "{} B", bytes)
        } else if bytes < 1024 * 1024 {
            write!(f, "{:.1} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            write!(f, "{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            write!(f, "{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_size_formatting() {
        assert_eq!(ByteSize::new(512).to_string(), "512 B");
        assert_eq!(ByteSize::new(1536).to_string(), "1.5 KB");
        assert_eq!(ByteSize::new(1572864).to_string(), "1.5 MB");
        assert_eq!(ByteSize::new(1610612736).to_string(), "1.5 GB");
    }
}
