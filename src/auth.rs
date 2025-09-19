use std::time::{SystemTime, UNIX_EPOCH};

pub fn get_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_generation() {
        let timestamp = get_timestamp();
        assert!(!timestamp.is_empty());
        assert!(timestamp.parse::<u64>().is_ok());
    }
}
