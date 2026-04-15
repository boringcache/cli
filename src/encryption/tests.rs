use super::*;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let (identity, recipient) = generate_keypair();
    let original = b"Hello, World! This is a test message.";

    let encrypted = encrypt_data(original, &recipient).unwrap();
    assert_ne!(encrypted, original.to_vec());

    let decrypted = decrypt_data(&encrypted, &identity).unwrap();
    assert_eq!(decrypted, original.to_vec());
}

#[test]
fn test_recipient_hint() {
    let full = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
    let hint = recipient_hint(full);
    assert_eq!(hint, "age1ql...ac8p");
}

#[test]
fn test_encrypt_stream_roundtrip() {
    let (identity, recipient) = generate_keypair();
    let original = b"Stream encryption test data that is a bit longer to test streaming.";

    let mut encrypted = Vec::new();
    encrypt_stream(original.as_slice(), &mut encrypted, &recipient).unwrap();

    let mut decrypted = Vec::new();
    decrypt_stream(encrypted.as_slice(), &mut decrypted, Some(&identity), None).unwrap();

    assert_eq!(decrypted, original.to_vec());
}
