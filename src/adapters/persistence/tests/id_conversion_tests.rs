use crate::adapters::persistence::id_conversion::{is_uuid_format, to_uuid};

#[test]
fn test_uuid_passthrough() {
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    assert_eq!(to_uuid(uuid), uuid);
}

#[test]
fn test_uuid_lowercase() {
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    assert_eq!(to_uuid(uuid), uuid);
}

#[test]
fn test_uuid_uppercase() {
    let uuid = "550E8400-E29B-41D4-A716-446655440000";
    assert_eq!(to_uuid(uuid), uuid);
}

#[test]
fn test_bigserial_conversion() {
    let bigint = "12345";
    let result = to_uuid(bigint);
    assert!(is_uuid_format(&result));
}

#[test]
fn test_integer_conversion() {
    let int = "789";
    let result = to_uuid(int);
    assert!(is_uuid_format(&result));
}

#[test]
fn test_deterministic_conversion() {
    let id = "12345";
    let result1 = to_uuid(id);
    let result2 = to_uuid(id);
    assert_eq!(result1, result2, "Conversion should be deterministic");
}

#[test]
fn test_different_ids_produce_different_uuids() {
    let id1 = to_uuid("12345");
    let id2 = to_uuid("12346");
    assert_ne!(id1, id2);
}

#[test]
fn test_is_uuid_format_valid() {
    assert!(is_uuid_format("550e8400-e29b-41d4-a716-446655440000"));
    assert!(is_uuid_format("550E8400-E29B-41D4-A716-446655440000"));
}

#[test]
fn test_is_uuid_format_invalid() {
    assert!(!is_uuid_format("12345")); // Not UUID format
    assert!(!is_uuid_format("550e8400-e29b-41d4-a716")); // Too short
    assert!(!is_uuid_format("550e8400-e29b-41d4-a716-44665544000")); // Wrong length
    assert!(!is_uuid_format("550e8400-e29b-41d4-a716-44665544000g")); // Invalid hex
    assert!(!is_uuid_format("550e840-e29b-41d4-a716-446655440000")); // Missing digit in first segment
}

#[test]
fn test_uuid_format_validation() {
    // Valid UUIDs
    let valid_uuids = vec![
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "550e8400-e29b-41d4-a716-446655440000",
    ];
    for uuid in valid_uuids {
        assert!(is_uuid_format(uuid), "Should recognize {} as UUID", uuid);
    }

    // Invalid UUIDs
    let invalid = vec![
        "550e8400e29b41d4a716446655440000", // No dashes
        "550e8400-e29b-41d4-a716-44665544000", // Missing digit
        "550e8400-e29b-41d4-a716-4466554400000", // Extra digit
        "g50e8400-e29b-41d4-a716-446655440000", // Non-hex character
    ];
    for id in invalid {
        assert!(!is_uuid_format(id), "Should reject {} as non-UUID", id);
    }
}
