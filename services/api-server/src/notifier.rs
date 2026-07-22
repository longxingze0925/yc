use serde_json::{json, Value};
use tracing::warn;

#[derive(Clone)]
pub struct SignalNotifier {
    push_url: Option<String>,
    service_token: String,
    client: reqwest::Client,
}

impl SignalNotifier {
    pub fn new(push_url: Option<String>, service_token: String) -> Self {
        Self {
            push_url,
            service_token,
            client: reqwest::Client::new(),
        }
    }

    pub fn disabled() -> Self {
        Self::new(None, String::new())
    }

    pub async fn push(&self, device_id: &str, message: Value) {
        let Some(url) = &self.push_url else {
            return;
        };
        let result = self
            .client
            .post(url)
            .bearer_auth(&self.service_token)
            .json(&json!({ "device_id": device_id, "message": message }))
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                warn!(
                    status = %response.status(),
                    %device_id,
                    "signal notification was rejected after persistence"
                );
            }
            Err(error) => {
                warn!(%error, %device_id, "signal notification delivery failed after persistence");
            }
        }
    }
}
