use super::*;

#[test]
fn parse_single_segment_manifest() {
    match parse_oci_path("my-cache/manifests/main") {
        Some(OciRoute::Manifest { name, reference }) => {
            assert_eq!(name, "my-cache");
            assert_eq!(reference, "main");
        }
        _ => panic!("expected Manifest"),
    }
}

#[test]
fn parse_multi_segment_manifest() {
    match parse_oci_path("org/cache/manifests/latest") {
        Some(OciRoute::Manifest { name, reference }) => {
            assert_eq!(name, "org/cache");
            assert_eq!(reference, "latest");
        }
        _ => panic!("expected Manifest"),
    }
}

#[test]
fn parse_deeply_nested_name() {
    match parse_oci_path("a/b/c/blobs/sha256:abc") {
        Some(OciRoute::Blob { name, digest }) => {
            assert_eq!(name, "a/b/c");
            assert_eq!(digest, "sha256:abc");
        }
        _ => panic!("expected Blob"),
    }
}

#[test]
fn parse_referrers_route() {
    match parse_oci_path("org/cache/referrers/sha256:abc") {
        Some(OciRoute::Referrers { name, digest }) => {
            assert_eq!(name, "org/cache");
            assert_eq!(digest, "sha256:abc");
        }
        _ => panic!("expected Referrers"),
    }
}

#[test]
fn parse_blob_upload_start() {
    match parse_oci_path("my-cache/blobs/uploads/") {
        Some(OciRoute::BlobUploadStart { name }) => {
            assert_eq!(name, "my-cache");
        }
        _ => panic!("expected BlobUploadStart"),
    }
}

#[test]
fn parse_blob_upload_start_without_trailing_slash() {
    match parse_oci_path("my-cache/blobs/uploads") {
        Some(OciRoute::BlobUploadStart { name }) => {
            assert_eq!(name, "my-cache");
        }
        _ => panic!("expected BlobUploadStart"),
    }
}

#[test]
fn parse_blob_upload_uuid() {
    match parse_oci_path("my-cache/blobs/uploads/some-uuid-here") {
        Some(OciRoute::BlobUpload { name, uuid }) => {
            assert_eq!(name, "my-cache");
            assert_eq!(uuid, "some-uuid-here");
        }
        _ => panic!("expected BlobUpload"),
    }
}

#[test]
fn parse_blob_upload_uuid_uses_last_upload_marker() {
    match parse_oci_path("org/blobs/uploads/cache/blobs/uploads/some-uuid-here") {
        Some(OciRoute::BlobUpload { name, uuid }) => {
            assert_eq!(name, "org/blobs/uploads/cache");
            assert_eq!(uuid, "some-uuid-here");
        }
        _ => panic!("expected BlobUpload"),
    }
}

#[test]
fn parse_blob_route_uses_last_blob_marker() {
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let path = format!("org/blobs/cache/blobs/{digest}");
    match parse_oci_path(&path) {
        Some(OciRoute::Blob {
            name,
            digest: parsed_digest,
        }) => {
            assert_eq!(name, "org/blobs/cache");
            assert_eq!(parsed_digest, digest);
        }
        _ => panic!("expected Blob"),
    }
}

#[test]
fn parse_leading_slash_stripped() {
    match parse_oci_path("/my-cache/manifests/v1") {
        Some(OciRoute::Manifest { name, reference }) => {
            assert_eq!(name, "my-cache");
            assert_eq!(reference, "v1");
        }
        _ => panic!("expected Manifest"),
    }
}

#[test]
fn parse_invalid_path_returns_none() {
    assert!(parse_oci_path("").is_none());
    assert!(parse_oci_path("just-a-name").is_none());
    assert!(parse_oci_path("/manifests/ref").is_none());
}
