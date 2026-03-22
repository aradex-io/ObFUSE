use super::{DnsBackend, DnsError, TxtRecord};
use async_trait::async_trait;
use log::debug;
use serde::{Deserialize, Serialize};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareBackend {
    client: reqwest::Client,
    token: String,
    zone_id: String,
}

#[derive(Deserialize, Debug)]
struct CfResponse<T> {
    success: bool,
    errors: Vec<CfError>,
    result: Option<T>,
    result_info: Option<CfResultInfo>,
}

#[derive(Deserialize, Debug)]
struct CfError {
    code: u32,
    message: String,
}

#[derive(Deserialize, Debug)]
struct CfResultInfo {
    #[allow(dead_code)]
    page: u32,
    #[allow(dead_code)]
    per_page: u32,
    #[allow(dead_code)]
    total_count: u32,
    total_pages: u32,
}

#[derive(Deserialize, Debug)]
struct CfRecord {
    id: String,
    name: String,
    content: String,
    #[serde(rename = "type")]
    record_type: String,
}

#[derive(Serialize)]
struct CreateRecordRequest<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

impl CloudflareBackend {
    pub fn new(token: String, zone_id: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        Self { client, token, zone_id }
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/zones/{}{}", CF_API_BASE, self.zone_id, path)
    }

    fn auth_header(&self) -> (&str, String) {
        ("Authorization", format!("Bearer {}", self.token))
    }
}

#[async_trait]
impl DnsBackend for CloudflareBackend {
    async fn create_record(&self, name: &str, content: &str, ttl: u32) -> Result<String, DnsError> {
        if content.len() > 2048 {
            return Err(DnsError::RecordTooLarge { size: content.len(), max: 2048 });
        }

        let body = CreateRecordRequest { record_type: "TXT", name, content, ttl };
        let (header_name, header_val) = self.auth_header();
        let resp = self.client
            .post(&self.api_url("/dns_records"))
            .header(header_name, header_val)
            .json(&body)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if resp.status() == 429 { return Err(DnsError::RateLimited); }

        let cf_resp: CfResponse<CfRecord> = resp.json().await
            .map_err(|e| DnsError::ApiError(e.to_string()))?;

        if !cf_resp.success {
            let msg = cf_resp.errors.iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>().join(", ");
            return Err(DnsError::ApiError(msg));
        }

        Ok(cf_resp.result.map(|r| r.id).unwrap_or_default())
    }

    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let (header_name, header_val) = self.auth_header();
        let url = format!("{}&type=TXT&name={}", self.api_url("/dns_records?per_page=100"), name);
        debug!("GET {}", url);

        let resp = self.client.get(&url)
            .header(header_name, header_val)
            .send().await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if resp.status() == 429 { return Err(DnsError::RateLimited); }

        let cf_resp: CfResponse<Vec<CfRecord>> = resp.json().await
            .map_err(|e| DnsError::ApiError(e.to_string()))?;

        match cf_resp.result {
            Some(records) => Ok(records.into_iter()
                .filter(|r| r.record_type == "TXT")
                .map(|r| TxtRecord { name: r.name, content: r.content, id: Some(r.id) })
                .collect()),
            None => Ok(vec![]),
        }
    }

    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError> {
        let (header_name, header_val) = self.auth_header();
        let url = self.api_url(&format!("/dns_records/{}", id));
        let body = serde_json::json!({ "content": content });

        let resp = self.client.patch(&url)
            .header(header_name, header_val)
            .json(&body).send().await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if resp.status() == 429 { return Err(DnsError::RateLimited); }

        let cf_resp: CfResponse<CfRecord> = resp.json().await
            .map_err(|e| DnsError::ApiError(e.to_string()))?;

        if !cf_resp.success {
            let msg = cf_resp.errors.iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>().join(", ");
            return Err(DnsError::ApiError(msg));
        }
        Ok(())
    }

    async fn delete_record(&self, id: &str) -> Result<(), DnsError> {
        let (header_name, header_val) = self.auth_header();
        let url = self.api_url(&format!("/dns_records/{}", id));
        let resp = self.client.delete(&url)
            .header(header_name, header_val)
            .send().await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if resp.status() == 429 { return Err(DnsError::RateLimited); }
        Ok(())
    }

    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let (header_name, header_val) = self.auth_header();
        let mut all_records = Vec::new();
        let mut page = 1u32;

        loop {
            let url = format!("{}&type=TXT&per_page=100&page={}",
                self.api_url("/dns_records?"), page);

            let resp = self.client.get(&url)
                .header(header_name, &header_val)
                .send().await
                .map_err(|e| DnsError::NetworkError(e.to_string()))?;

            if resp.status() == 429 { return Err(DnsError::RateLimited); }

            let cf_resp: CfResponse<Vec<CfRecord>> = resp.json().await
                .map_err(|e| DnsError::ApiError(e.to_string()))?;

            if let Some(records) = cf_resp.result {
                for r in records {
                    if r.record_type == "TXT" && r.name.contains(prefix) {
                        all_records.push(TxtRecord {
                            name: r.name, content: r.content, id: Some(r.id),
                        });
                    }
                }
            }

            match cf_resp.result_info {
                Some(info) if page < info.total_pages => page += 1,
                _ => break,
            }
        }
        Ok(all_records)
    }
}
