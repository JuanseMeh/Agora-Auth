//! Tests for ExternalIdentityRepository port.

use crate::core::usecases::ports::ExternalIdentityRepository;
use uuid::Uuid;
use futures::future::{self, BoxFuture};

#[derive(Clone)]
struct MockRepo;

impl ExternalIdentityRepository for MockRepo {
    fn find_by_provider_user(&self, provider: &str, provider_user_id: &str) -> BoxFuture<'_, Result<Option<Uuid>, anyhow::Error>> {
        if provider == "google" && provider_user_id == "123456" {
            let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();
            Box::pin(future::ok(Some(id)))
        } else {
            Box::pin(future::ok(None))
        }
    }

    fn upsert(&self, _provider: &str, _provider_user_id: &str, user_id: Uuid, _email: Option<&str>) -> BoxFuture<'_, Result<Uuid, anyhow::Error>> {
        Box::pin(future::ok(user_id))
    }

    fn delete(&self, _provider: &str, _provider_user_id: &str) -> BoxFuture<'_, Result<(), anyhow::Error>> {
        Box::pin(future::ok(()))
    }
}

#[tokio::test]
async fn find_by_provider_user_returns_existing() {
    let repo = MockRepo;
    let result = repo.find_by_provider_user("google", "123456").await.unwrap();
    let expected = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();
    assert_eq!(result, Some(expected));
}

#[tokio::test]
async fn find_by_provider_user_not_found_returns_none() {
    let repo = MockRepo;
    let result = repo.find_by_provider_user("github", "999").await.unwrap();
    assert_eq!(result, None);
}

#[tokio::test]
async fn upsert_returns_user_id() {
    let repo = MockRepo;
    let user_id = Uuid::new_v4();
    let result = repo.upsert("google", "123", user_id, Some("test@example.com")).await.unwrap();
    assert_eq!(result, user_id);
}

#[tokio::test]
async fn delete_succeeds() {
    let repo = MockRepo;
    repo.delete("google", "123456").await.unwrap();
}

