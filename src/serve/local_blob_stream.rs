const TINY_BLOB_MAX_BYTES: u64 = 32 * 1024;
const SMALL_BLOB_MAX_BYTES: u64 = 256 * 1024;
const MEDIUM_BLOB_MAX_BYTES: u64 = 16 * 1024 * 1024;

const TINY_STREAM_BUFFER_BYTES: usize = 16 * 1024;
const SMALL_STREAM_BUFFER_BYTES: usize = 64 * 1024;
const MEDIUM_STREAM_BUFFER_BYTES: usize = 256 * 1024;
const LARGE_STREAM_BUFFER_BYTES: usize = 1024 * 1024;

pub(crate) fn buffer_bytes_for(size_bytes: u64) -> usize {
    if size_bytes <= TINY_BLOB_MAX_BYTES {
        TINY_STREAM_BUFFER_BYTES
    } else if size_bytes <= SMALL_BLOB_MAX_BYTES {
        SMALL_STREAM_BUFFER_BYTES
    } else if size_bytes <= MEDIUM_BLOB_MAX_BYTES {
        MEDIUM_STREAM_BUFFER_BYTES
    } else {
        LARGE_STREAM_BUFFER_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_buffer_scales_with_blob_size() {
        assert_eq!(buffer_bytes_for(1), TINY_STREAM_BUFFER_BYTES);
        assert_eq!(buffer_bytes_for(32 * 1024), TINY_STREAM_BUFFER_BYTES);
        assert_eq!(buffer_bytes_for(32 * 1024 + 1), SMALL_STREAM_BUFFER_BYTES);
        assert_eq!(buffer_bytes_for(256 * 1024), SMALL_STREAM_BUFFER_BYTES);
        assert_eq!(buffer_bytes_for(256 * 1024 + 1), MEDIUM_STREAM_BUFFER_BYTES);
        assert_eq!(
            buffer_bytes_for(16 * 1024 * 1024),
            MEDIUM_STREAM_BUFFER_BYTES
        );
        assert_eq!(
            buffer_bytes_for(16 * 1024 * 1024 + 1),
            LARGE_STREAM_BUFFER_BYTES
        );
    }
}
