//! JWKS provider for Google RS256 keys.

use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use rsa::{RsaPublicKey, BigUint};
use dashmap::DashMap;
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<JwksKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    pub kid: String,
    pub kty: String,
    #[serde(rename = "n")]
    pub modulus: String,
    #[serde(rename = "e")]
    pub exponent: String,
}

#[derive(Debug, Clone)]
pub struct JwksProvider {
    http_client: Client,
    jwks_url: String,
    cache: DashMap<String, (Arc<RsaPublicKey>, Instant)>,
}

impl JwksProvider {
    pub fn new(jwks_url: String) -> Self {
        Self {
            http_client: Client::new(),
            jwks_url,
            cache: DashMap::new(),
        }
    }

    pub async fn fetch_jwks(&self) -> Result<JwksDocument> {
        let response = self.http_client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("jwks fetch: {}", e))?;

        response
            .json::<JwksDocument>()
            .await
            .map_err(|e| anyhow::anyhow!("jwks parse: {}", e))
    }

    pub async fn get_key(&self, kid: &str) -> Option<Arc<RsaPublicKey>> {
        // Check cache
        if let Some(entry) = self.cache.get(kid) {
            let (key, cached_at) = entry.value();
            if Instant::now().duration_since(*cached_at) < JWKS_CACHE_TTL {
                return Some(key.clone());
            }
        }

        // Remove expired
        let _ = self.cache.remove(kid);

        let jwks = self.fetch_jwks().await.ok()?;
        for jwk in jwks.keys {
            if jwk.kid == *kid {
                let n_bytes = URL_SAFE_NO_PAD.decode(&jwk.modulus).ok()?;
                let e_bytes = URL_SAFE_NO_PAD.decode(&jwk.exponent).ok()?;

                let n = BigUint::from_bytes_be(&n_bytes);
                let e = BigUint::from_bytes_be(&e_bytes);

                if let Ok(key) = RsaPublicKey::new(n, e) {
                    let key_arc = Arc::new(key);
                    self.cache.insert(kid.to_string(), (key_arc.clone(), Instant::now()));
                    return Some(key_arc);
                }
            }
        }
        None
    }
}

