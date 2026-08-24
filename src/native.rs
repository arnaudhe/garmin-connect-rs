//! Constants and helpers mirroring the module-level constants at the top of
//! the Python `client.py` (client IDs, user agents, DI auth constants, etc).

use base64::Engine as _;
use wreq::header::{HeaderMap, HeaderName, HeaderValue};

pub const IOS_SSO_CLIENT_ID: &str = "GCM_IOS_DARK";
pub const IOS_LOGIN_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) \
    AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148";

pub const PORTAL_SSO_CLIENT_ID: &str = "GarminConnect";
pub const DESKTOP_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Anti-WAF delay bounds (seconds) for the portal flow — Cloudflare flags
/// rapid GET -> POST sequences as bot-like.
pub const LOGIN_DELAY_MIN_S: f64 = 10.0;
pub const LOGIN_DELAY_MAX_S: f64 = 20.0;

pub const NATIVE_API_USER_AGENT: &str = "GCM-Android-5.23";
pub const NATIVE_X_GARMIN_USER_AGENT: &str =
    "com.garmin.android.apps.connectmobile/5.23; ; Google/sdk_gphone64_arm64/google; \
     Android/33; Dalvik/2.1.0";

pub const DI_GRANT_TYPE: &str =
    "https://connectapi.garmin.com/di-oauth2-service/oauth/grant/service_ticket";

/// Client IDs tried in order during DI OAuth2 service-ticket exchange.
pub const DI_CLIENT_IDS: &[&str] = &[
    "GARMIN_CONNECT_MOBILE_ANDROID_DI_2025Q2",
    "GARMIN_CONNECT_MOBILE_ANDROID_DI_2024Q4",
    "GARMIN_CONNECT_MOBILE_ANDROID_DI",
    "GARMIN_CONNECT_MOBILE_IOS_DI",
];

pub fn build_basic_auth(client_id: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:"))
    )
}

/// Headers sent on every native (DI Bearer) API call — equivalent of
/// Python's `_native_headers`.
pub fn native_headers(extra: &[(&str, String)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let insert = |h: &mut HeaderMap, k: &'static str, v: &str| {
        if let Ok(val) = HeaderValue::from_str(v) {
            h.insert(HeaderName::from_static(k), val);
        }
    };
    insert(&mut headers, "user-agent", NATIVE_API_USER_AGENT);
    insert(&mut headers, "x-garmin-user-agent", NATIVE_X_GARMIN_USER_AGENT);
    insert(&mut headers, "x-garmin-paired-app-version", "10861");
    insert(&mut headers, "x-garmin-client-platform", "Android");
    insert(&mut headers, "x-app-ver", "10861");
    insert(&mut headers, "x-lang", "en");
    insert(&mut headers, "x-gcexperience", "GC5");
    insert(&mut headers, "accept-language", "en-US,en;q=0.9");
    for (k, v) in extra {
        if let (Ok(name), Ok(val)) = (HeaderName::try_from(*k), HeaderValue::from_str(v)) {
            headers.insert(name, val);
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_basic_auth_encodes_client_id_with_trailing_colon_and_no_password() {
        let header = build_basic_auth("my-client-id");

        let encoded = header
            .strip_prefix("Basic ")
            .expect("header should start with 'Basic '");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("payload should be valid standard base64");
        assert_eq!(decoded, b"my-client-id:");
    }

    #[test]
    fn native_headers_sets_expected_defaults() {
        let headers = native_headers(&[]);

        assert_eq!(headers.get("user-agent").unwrap(), NATIVE_API_USER_AGENT);
        assert_eq!(
            headers.get("x-garmin-user-agent").unwrap(),
            NATIVE_X_GARMIN_USER_AGENT
        );
        assert_eq!(headers.get("x-garmin-client-platform").unwrap(), "Android");
        assert_eq!(headers.get("x-gcexperience").unwrap(), "GC5");
    }

    #[test]
    fn native_headers_applies_and_overrides_with_extra_headers() {
        let headers = native_headers(&[
            ("authorization", "Bearer abc123".to_string()),
            ("x-lang", "fr".to_string()),
        ]);

        assert_eq!(headers.get("authorization").unwrap(), "Bearer abc123");
        // "x-lang" has a "en" default set earlier in the function; extras
        // must win since they're inserted last.
        assert_eq!(headers.get("x-lang").unwrap(), "fr");
    }

    #[test]
    fn native_headers_ignores_invalid_extra_header_values() {
        // A raw newline is not a legal header value; it must be silently
        // dropped rather than panicking or poisoning the map.
        let headers = native_headers(&[("x-bad", "line1\nline2".to_string())]);
        assert!(headers.get("x-bad").is_none());
    }
}
