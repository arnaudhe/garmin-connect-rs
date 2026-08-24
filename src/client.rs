//! Rust port of `garminconnect/client.py`'s `Client` class.
//!
//! Ported behaviour:
//!   - Cascading login strategy chain: mobile (impersonated -> plain) then
//!     portal (impersonated -> plain). The Python "widget" (HTML-scraped SSO
//!     embed) strategy is NOT ported — it exists upstream mainly as a
//!     clientId-rate-limit bypass and its MFA path can't be trusted to have
//!     actually triggered OTP delivery. Add it later if you hit rate limits
//!     the other four strategies can't clear.
//!   - Native DI OAuth2 Bearer token exchange (primary auth), with JWT_WEB
//!     cookie auth as a fallback when the DI exchange is rejected.
//!   - MFA support via an explicit resumable `MfaContext`.
//!   - Token persistence to disk (0600 permissions) and refresh-on-expiry.
//!   - A generic `connectapi` / `get` / `post` / `put` / `delete` / `download`
//!     surface mirroring the Python `_run_request` behaviour, including
//!     401 -> refresh -> retry-once and 404 -> "not found" error mapping.
//!
//! Browser TLS/JA3/JA4 impersonation is done with the `wreq` crate (a
//! maintained hard-fork of `reqwest`) — the closest Rust equivalent to
//! Python's `curl_cffi`. Emulation profile names (`wreq_util::Emulation::*`)
//! are version-specific; if a variant below doesn't compile, run
//! `cargo doc -p wreq-util --open` and swap in whatever your locked version
//! exposes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wreq::cookie::{CookieStore, Cookies, Jar};
use wreq::header::{HeaderMap, HeaderName, HeaderValue};
use wreq::{Client, Method, StatusCode, Version};
use wreq_util::{Emulation, Profile};

/// A login-flow HTTP client paired with an explicit cookie jar. We need the
/// jar handle (rather than the opaque built-in `cookie_store(true)` store)
/// so we can read the `JWT_WEB` cookie back out after ticket consumption —
/// mirrors reading `sess.cookies.jar` in the Python implementation.
#[derive(Clone)]
struct LoginSession {
    client: Client,
    jar: Arc<Jar>,
}

impl LoginSession {
    fn new(emulation: Option<Profile>) -> Result<Self> {
        let jar = Arc::new(Jar::default());
        let mut builder = Client::builder().cookie_provider(jar.clone());
        if let Some(e) = emulation {
            builder = builder.emulation(e);
        }
        Ok(Self {
            client: builder.build()?,
            jar,
        })
    }
}

use crate::error::{GarminError, Result};
use crate::native::{
    build_basic_auth, native_headers, DESKTOP_USER_AGENT, DI_CLIENT_IDS, DI_GRANT_TYPE,
    IOS_LOGIN_UA, IOS_SSO_CLIENT_ID, LOGIN_DELAY_MAX_S, LOGIN_DELAY_MIN_S, PORTAL_SSO_CLIENT_ID,
};

/// TLS impersonation profiles rotated through for the mobile flow.
/// Different fingerprints land in different Cloudflare rate-limit buckets.
const MOBILE_IMPERSONATIONS: &[Profile] =
    &[Emulation::SafariIos18_1_1, Emulation::Safari18, Emulation::Chrome131];

/// TLS impersonation profiles rotated through for the portal flow.
const PORTAL_IMPERSONATIONS: &[Profile] = &[
    Emulation::Safari18,
    Emulation::SafariIos18_1_1,
    Emulation::Chrome131,
    Emulation::Edge131,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaFlow {
    Ios,
    Portal,
}

impl MfaFlow {
    fn path_segment(self) -> &'static str {
        match self {
            MfaFlow::Ios => "mobile",
            MfaFlow::Portal => "portal",
        }
    }
}

/// Everything needed to complete a login that stopped at an MFA challenge.
/// Obtained from [`GarminClient::login`], consumed by
/// [`GarminClient::resume_login`].
pub struct MfaContext {
    flow: MfaFlow,
    session: LoginSession,
    login_params: HashMap<String, String>,
    post_headers: HeaderMap,
    service_url: String,
    mfa_method: String,
}

pub enum LoginOutcome {
    Success,
    NeedsMfa(MfaContext),
}

impl std::fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginSession").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MfaContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaContext")
            .field("flow", &self.flow)
            .field("mfa_method", &self.mfa_method)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize, Default)]
struct TokenData {
    di_token: Option<String>,
    di_refresh_token: Option<String>,
    di_client_id: Option<String>,
}

pub struct GarminClient {
    domain: String,
    sso: String,
    connect: String,
    connectapi: String,
    ios_service_url: String,
    portal_service_url: String,
    #[allow(dead_code)]
    mobile_sso_service_url: String,
    di_token_url: String,

    // Native Bearer tokens (primary auth).
    di_token: Option<String>,
    di_refresh_token: Option<String>,
    di_client_id: Option<String>,

    // JWT_WEB cookie auth (fallback when DI token exchange fails).
    jwt_web: Option<String>,

    /// Dedicated client for one-off calls to the DI auth host (token
    /// exchange / refresh). Impersonated so it isn't trivially flagged.
    auth_client: Client,
    /// Long-lived client for `connectapi` calls — auth travels in headers
    /// per-call, so no cookie jar is needed or wanted here.
    api_client: Client,

    /// Strategy names to skip during login, e.g. `{"mobile+impersonated"}`.
    /// Valid: mobile+impersonated, mobile+plain, portal+impersonated, portal+plain
    pub skip_strategies: std::collections::HashSet<String>,
    /// Verify each strategy's token against the API tier before accepting it
    /// (mirrors the Python `verify_login` flag). Default true.
    pub verify_login: bool,

    tokenstore_path: Option<PathBuf>,
}

impl GarminClient {
    pub fn new(domain: &str) -> Result<Self> {
        let auth_client = Client::builder()
            .emulation(Emulation::Chrome131)
            .cookie_store(true)
            .build()?;
        let api_client = Client::builder().build()?;

        Ok(Self {
            domain: domain.to_string(),
            sso: format!("https://sso.{domain}"),
            connect: format!("https://connect.{domain}"),
            connectapi: format!("https://connectapi.{domain}"),
            ios_service_url: format!("https://mobile.integration.{domain}/gcm/ios"),
            portal_service_url: format!("https://connect.{domain}/app"),
            mobile_sso_service_url: format!("https://mobile.integration.{domain}/gcm/android"),
            di_token_url: format!("https://diauth.{domain}/di-oauth2-service/oauth/token"),
            di_token: None,
            di_refresh_token: None,
            di_client_id: None,
            jwt_web: None,
            auth_client,
            api_client,
            skip_strategies: Default::default(),
            verify_login: true,
            tokenstore_path: None,
        })
    }

    pub fn is_authenticated(&self) -> bool {
        self.di_token.is_some() || self.jwt_web.is_some()
    }

    // ------------------------------------------------------------------ //
    //  LOGIN CHAIN                                                       //
    // ------------------------------------------------------------------ //

    /// Try each login strategy in order. Only credential errors stop the
    /// chain immediately; everything else (429s, transport errors, HTML
    /// challenges) falls through to the next strategy.
    pub async fn login(&mut self, email: &str, password: &str) -> Result<LoginOutcome> {
        let strategies: Vec<(&str, MfaFlow, bool)> = vec![
            ("mobile+impersonated", MfaFlow::Ios, true),
            ("mobile+plain", MfaFlow::Ios, false),
            ("portal+impersonated", MfaFlow::Portal, true),
            ("portal+plain", MfaFlow::Portal, false),
        ];

        let mut last_err: Option<GarminError> = None;
        let mut rate_limited = 0usize;
        let total = strategies
            .iter()
            .filter(|(name, ..)| !self.skip_strategies.contains(*name))
            .count();

        for (name, flow, impersonate) in strategies {
            if self.skip_strategies.contains(name) {
                continue;
            }

            let attempt = match flow {
                MfaFlow::Ios => self.mobile_login(email, password, impersonate).await,
                MfaFlow::Portal => self.portal_login(email, password, impersonate).await,
            };

            match attempt {
                Ok((ticket, session, service_url)) => {
                    if let Err(e) = self
                        .establish_session(&ticket, &session, &service_url)
                        .await
                    {
                        last_err = Some(e);
                        continue;
                    }
                    if self.verify_login && !self.verify_token().await {
                        self.clear_auth_state();
                        last_err = Some(GarminError::Connection(format!(
                            "{name}: token rejected by API tier"
                        )));
                        continue;
                    }
                    return Ok(LoginOutcome::Success);
                }
                Err(GarminError::Authentication(msg)) => {
                    return Err(GarminError::Authentication(msg));
                }
                Err(GarminError::MfaRequired(ctx)) => {
                    return Ok(LoginOutcome::NeedsMfa(ctx));
                }
                Err(GarminError::TooManyRequests(msg)) => {
                    rate_limited += 1;
                    last_err = Some(GarminError::TooManyRequests(msg));
                    continue;
                }
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }

        if rate_limited == total && total > 0 {
            return Err(GarminError::TooManyRequests(
                "All login strategies rate limited (429). Try again later.".into(),
            ));
        }
        Err(GarminError::Connection(format!(
            "All login strategies exhausted: {last_err:?}",
        )))
    }

    /// Complete a login that returned `LoginOutcome::NeedsMfa`.
    pub async fn resume_login(&mut self, ctx: MfaContext, mfa_code: &str) -> Result<()> {
        let flow_path = ctx.flow.path_segment();
        let url = format!("{}/{}/api/mfa/verifyCode", self.sso, flow_path);

        let body = serde_json::json!({
            "mfaMethod": ctx.mfa_method,
            "mfaVerificationCode": mfa_code,
            "rememberMyBrowser": true,
            "reconsentList": [],
            "mfaSetup": false,
        });

        let query: Vec<(String, String)> = ctx.login_params.clone().into_iter().collect();
        let resp = ctx
            .session
            .client
            .post(&url)
            .query(&query)
            .headers(ctx.post_headers.clone())
            .json(&body)
            .send()
            .await?;

        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(GarminError::TooManyRequests(
                "MFA verification returned 429".into(),
            ));
        }

        let res: Value = resp.json().await.map_err(|e| {
            GarminError::Connection(format!("MFA verify: non-JSON response ({e})"))
        })?;

        if res["responseStatus"]["type"] == "SUCCESSFUL" {
            let ticket = res["serviceTicketId"]
                .as_str()
                .ok_or_else(|| GarminError::Authentication("MFA: missing service ticket".into()))?
                .to_string();
            self.establish_session(&ticket, &ctx.session, &ctx.service_url)
                .await?;
            if self.verify_login && !self.verify_token().await {
                self.clear_auth_state();
                return Err(GarminError::Connection(
                    "token rejected by API tier after MFA".into(),
                ));
            }
            return Ok(());
        }

        Err(GarminError::Authentication(format!(
            "MFA verification failed: {res}"
        )))
    }

    fn clear_auth_state(&mut self) {
        self.di_token = None;
        self.di_refresh_token = None;
        self.di_client_id = None;
        self.jwt_web = None;
    }

    async fn verify_token(&mut self) -> bool {
        match self.connectapi("/userprofile-service/socialProfile", None).await {
            Ok(_) => true,
            Err(GarminError::Connection(msg)) => !(msg.contains("401") || msg.contains("403")),
            Err(_) => true, // inconclusive (transport/5xx) — keep the token
        }
    }

    // ------------------------------------------------------------------ //
    //  STRATEGY: mobile (iOS app flow)                                   //
    // ------------------------------------------------------------------ //

    async fn mobile_login(
        &self,
        email: &str,
        password: &str,
        impersonate: bool,
    ) -> Result<(String, LoginSession, String)> {
        if impersonate {
            let mut last_err: Option<GarminError> = None;
            for profile in MOBILE_IMPERSONATIONS {
                let session = LoginSession::new(Some(*profile))?;
                match self.do_mobile_login(&session, email, password).await {
                    Ok(ticket) => return Ok((ticket, session, self.ios_service_url.clone())),
                    Err(e @ GarminError::Authentication(_)) => return Err(e),
                    Err(e @ GarminError::MfaRequired(_)) => return Err(e),
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| {
                GarminError::Connection("mobile+impersonated: no profile worked".into())
            }))
        } else {
            let session = LoginSession::new(None)?;
            let ticket = self.do_mobile_login(&session, email, password).await?;
            Ok((ticket, session, self.ios_service_url.clone()))
        }
    }

    async fn do_mobile_login(&self, session: &LoginSession, email: &str, password: &str) -> Result<String> {
        let url = format!("{}/mobile/api/login", self.sso);
        let params = [
            ("clientId", IOS_SSO_CLIENT_ID),
            ("locale", "en-US"),
            ("service", &self.ios_service_url),
        ];

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static(IOS_LOGIN_UA),
        );
        headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("application/json, text/plain, */*"),
        );
        headers.insert(
            HeaderName::from_static("origin"),
            HeaderValue::from_str(&self.sso).unwrap(),
        );

        let resp = session
            .client
            .post(&url)
            .query(&params)
            .headers(headers)
            .json(&serde_json::json!({
                "username": email,
                "password": password,
                "rememberMe": true,
                "captchaToken": "",
            }))
            .send()
            .await?;

        self.parse_login_response(resp, MfaFlow::Ios, session, &self.ios_service_url, "mobile")
            .await
    }

    // ------------------------------------------------------------------ //
    //  STRATEGY: portal (desktop browser flow)                           //
    // ------------------------------------------------------------------ //

    async fn portal_login(
        &self,
        email: &str,
        password: &str,
        impersonate: bool,
    ) -> Result<(String, LoginSession, String)> {
        if impersonate {
            let mut last_err: Option<GarminError> = None;
            for profile in PORTAL_IMPERSONATIONS {
                let session = LoginSession::new(Some(*profile))?;
                match self.do_portal_login(&session, email, password).await {
                    Ok(ticket) => return Ok((ticket, session, self.portal_service_url.clone())),
                    Err(e @ GarminError::Authentication(_)) => return Err(e),
                    Err(e @ GarminError::MfaRequired(_)) => return Err(e),
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| {
                GarminError::Connection("portal+impersonated: no profile worked".into())
            }))
        } else {
            let session = LoginSession::new(None)?;
            let ticket = self.do_portal_login(&session, email, password).await?;
            Ok((ticket, session, self.portal_service_url.clone()))
        }
    }

    async fn do_portal_login(&self, session: &LoginSession, email: &str, password: &str) -> Result<String> {
        let signin_url = format!("{}/portal/sso/en-US/sign-in", self.sso);

        // Step 1: GET the sign-in page to establish cookies.
        let get_resp = session
            .client
            .get(&signin_url)
            .query(&[
                ("clientId", PORTAL_SSO_CLIENT_ID),
                ("service", &self.portal_service_url),
            ])
            .header("user-agent", DESKTOP_USER_AGENT)
            .header(
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .send()
            .await?;

        if get_resp.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(GarminError::TooManyRequests(
                "Portal login GET returned 429".into(),
            ));
        }

        // Anti-WAF delay: mimics real "read then type" browser behaviour.
        let delay_s =
            rand::thread_rng().gen_range(LOGIN_DELAY_MIN_S..LOGIN_DELAY_MAX_S);
        tokio::time::sleep(std::time::Duration::from_secs_f64(delay_s)).await;

        // Step 2: POST credentials.
        let params = [
            ("clientId", PORTAL_SSO_CLIENT_ID.to_string()),
            ("locale", "en-US".to_string()),
            ("service", self.portal_service_url.clone()),
        ];

        let referer = format!(
            "{signin_url}?clientId={PORTAL_SSO_CLIENT_ID}&service={}",
            self.portal_service_url
        );

        let resp = session
            .client
            .post(format!("{}/portal/api/login", self.sso))
            .query(&params)
            .header("user-agent", DESKTOP_USER_AGENT)
            .header("accept", "application/json, text/plain, */*")
            .header("origin", self.sso.as_str())
            .header("referer", referer)
            .json(&serde_json::json!({
                "username": email,
                "password": password,
                "rememberMe": true,
                "captchaToken": "",
            }))
            .send()
            .await?;

        self.parse_login_response(resp, MfaFlow::Portal, session, &self.portal_service_url, "portal")
            .await
    }

    /// Shared response handling for the mobile/portal JSON login APIs.
    async fn parse_login_response(
        &self,
        resp: wreq::Response,
        flow: MfaFlow,
        session: &LoginSession,
        service_url: &str,
        mfa_method_default: &str,
    ) -> Result<String> {
        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(GarminError::TooManyRequests(format!(
                "{:?} login returned 429",
                flow
            )));
        }
        if status == StatusCode::FORBIDDEN {
            return Err(GarminError::Connection(
                "HTTP 403 (bot challenge) — falling through to next strategy".into(),
            ));
        }

        let res: Value = resp
            .json()
            .await
            .map_err(|e| GarminError::Connection(format!("login: non-JSON response ({e})")))?;

        match res["responseStatus"]["type"].as_str() {
            Some("MFA_REQUIRED") => {
                let mfa_method = res["customerMfaInfo"]["mfaLastMethodUsed"]
                    .as_str()
                    .unwrap_or(mfa_method_default)
                    .to_string();

                let login_params: HashMap<String, String> = match flow {
                    MfaFlow::Ios => [
                        ("clientId".into(), IOS_SSO_CLIENT_ID.into()),
                        ("locale".into(), "en-US".into()),
                        ("service".into(), self.ios_service_url.clone()),
                    ]
                    .into(),
                    MfaFlow::Portal => [
                        ("clientId".into(), PORTAL_SSO_CLIENT_ID.into()),
                        ("locale".into(), "en-US".into()),
                        ("service".into(), self.portal_service_url.clone()),
                    ]
                    .into(),
                };

                let mut post_headers = HeaderMap::new();
                post_headers.insert(
                    HeaderName::from_static("content-type"),
                    HeaderValue::from_static("application/json"),
                );

                Err(GarminError::MfaRequired(MfaContext {
                    flow,
                    session: session.clone(),
                    login_params,
                    post_headers,
                    service_url: service_url.to_string(),
                    mfa_method,
                }))
            }
            Some("SUCCESSFUL") => {
                let ticket = res["serviceTicketId"]
                    .as_str()
                    .ok_or_else(|| GarminError::Connection("login: missing service ticket".into()))?
                    .to_string();
                Ok(ticket)
            }
            Some("INVALID_USERNAME_PASSWORD") => Err(GarminError::Authentication(
                "401 Unauthorized (Invalid Username or Password)".into(),
            )),
            Some("CAPTCHA_REQUIRED") => Err(GarminError::Connection(
                "CAPTCHA required (bot challenge) — falling through to next strategy".into(),
            )),
            _ => {
                if res["error"]["status-code"] == "429" {
                    return Err(GarminError::TooManyRequests("429 in JSON body".into()));
                }
                Err(GarminError::Connection(format!("login failed: {res}")))
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  SESSION ESTABLISHMENT — DI token first, JWT_WEB fallback          //
    // ------------------------------------------------------------------ //

    async fn establish_session(
        &mut self,
        ticket: &str,
        session: &LoginSession,
        service_url: &str,
    ) -> Result<()> {
        if self.exchange_service_ticket(ticket, service_url).await.is_ok() {
            return Ok(());
        }

        // Fallback: consume the ticket via connect.<domain> to pick up the
        // JWT_WEB cookie. `session.jar` already holds the CAS session
        // cookies set during login (equivalent of Python's `sess.cookies.jar`).
        let resp = session
            .client
            .get(service_url)
            .query(&[("ticket", ticket)])
            .send()
            .await?;
        let _ = resp.bytes().await; // drive redirects; body unused

        let uri: wreq::Uri = service_url.parse().map_err(|e| {
            GarminError::Connection(format!("invalid service_url for cookie lookup: {e}"))
        })?;

        let cookie_headers: Vec<HeaderValue> = match session.jar.cookies(&uri, Version::HTTP_11) {
            Cookies::Compressed(v) => vec![v],
            Cookies::Uncompressed(vs) => vs,
            Cookies::Empty => Vec::new(),
            _ => Vec::new(),
        };
        if cookie_headers.is_empty() {
            return Err(GarminError::Authentication(
                "no cookies set after ticket consumption".into(),
            ));
        }

        let jwt_web = cookie_headers
            .iter()
            .filter_map(|h| h.to_str().ok())
            .flat_map(|s| s.split(';'))
            .map(str::trim)
            .find_map(|kv| kv.strip_prefix("JWT_WEB=").map(str::to_string))
            .ok_or_else(|| {
                GarminError::Authentication("JWT_WEB cookie not set after ticket consumption".into())
            })?;

        self.jwt_web = Some(jwt_web);
        Ok(())
    }

    async fn exchange_service_ticket(&mut self, ticket: &str, service_url: &str) -> Result<()> {
        for client_id in DI_CLIENT_IDS {
            let mut headers = native_headers(&[(
                "authorization",
                build_basic_auth(client_id),
            )]);
            headers.insert(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );

            let form = [
                ("client_id", *client_id),
                ("service_ticket", ticket),
                ("grant_type", DI_GRANT_TYPE),
                ("service_url", service_url),
            ];

            let resp = self
                .auth_client
                .post(&self.di_token_url)
                .headers(headers)
                .form(&form)
                .send()
                .await?;

            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                return Err(GarminError::TooManyRequests(
                    "DI token exchange rate limited".into(),
                ));
            }
            if !resp.status().is_success() {
                continue;
            }

            let data: Value = match resp.json().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(access_token) = data["access_token"].as_str() else {
                continue;
            };

            self.di_client_id = Some(
                extract_client_id_from_jwt(access_token).unwrap_or_else(|| client_id.to_string()),
            );
            self.di_token = Some(access_token.to_string());
            self.di_refresh_token = data["refresh_token"].as_str().map(str::to_string);
            return Ok(());
        }

        Err(GarminError::Authentication(
            "DI token exchange failed for all client IDs".into(),
        ))
    }

    async fn refresh_di_token(&mut self) -> Result<()> {
        let (Some(refresh_token), Some(client_id)) =
            (self.di_refresh_token.clone(), self.di_client_id.clone())
        else {
            return Err(GarminError::Authentication(
                "No DI refresh token available".into(),
            ));
        };

        let mut headers = native_headers(&[("authorization", build_basic_auth(&client_id))]);
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ];

        let resp = self
            .auth_client
            .post(&self.di_token_url)
            .headers(headers)
            .form(&form)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(GarminError::Authentication(format!(
                "DI token refresh failed: {status} {text}"
            )));
        }

        let data: Value = resp.json().await?;
        let access_token = data["access_token"]
            .as_str()
            .ok_or_else(|| GarminError::Authentication("DI refresh: missing access_token".into()))?;

        self.di_client_id = Some(
            extract_client_id_from_jwt(access_token).unwrap_or_else(|| client_id.clone()),
        );
        self.di_token = Some(access_token.to_string());
        if let Some(rt) = data["refresh_token"].as_str() {
            self.di_refresh_token = Some(rt.to_string());
        }
        Ok(())
    }

    fn token_expires_soon(&self) -> bool {
        let Some(token) = self.di_token.as_ref() else {
            return false;
        };
        let Some(exp) = jwt_exp(token) else {
            return false;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        now > (exp - 900)
    }

    async fn refresh_session(&mut self) -> Result<()> {
        if self.di_token.is_some() {
            self.refresh_di_token().await?;
            if let Some(path) = self.tokenstore_path.clone() {
                let _ = self.dump(&path);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------ //
    //  TOKEN PERSISTENCE                                                 //
    // ------------------------------------------------------------------ //

    pub fn dumps(&self) -> Result<String> {
        let data = TokenData {
            di_token: self.di_token.clone(),
            di_refresh_token: self.di_refresh_token.clone(),
            di_client_id: self.di_client_id.clone(),
        };
        Ok(serde_json::to_string(&data)?)
    }

    /// Write tokens to disk with owner-only permissions (0600 file inside a
    /// 0700 directory), matching the Python implementation's hardening
    /// against world-readable token leaks on shared hosts.
    pub fn dump(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = token_file_path(path.as_ref());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        std::fs::write(&path, self.dumps()?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        self.tokenstore_path = Some(path.to_path_buf());
        let resolved = token_file_path(path);
        let contents = std::fs::read_to_string(resolved)?;
        self.loads(&contents)
    }

    pub fn loads(&mut self, tokenstore: &str) -> Result<()> {
        let data: TokenData = serde_json::from_str(tokenstore)?;
        self.di_token = data.di_token;
        self.di_refresh_token = data.di_refresh_token;
        self.di_client_id = data.di_client_id;
        if !self.is_authenticated() {
            return Err(GarminError::Authentication(
                "Missing tokens from loaded token store".into(),
            ));
        }
        Ok(())
    }

    // ------------------------------------------------------------------ //
    //  GENERIC API SURFACE                                               //
    // ------------------------------------------------------------------ //

    fn api_headers(&self) -> Result<HeaderMap> {
        if !self.is_authenticated() {
            return Err(GarminError::Authentication("Not authenticated".into()));
        }
        if let Some(token) = &self.di_token {
            let mut h = native_headers(&[("authorization", format!("Bearer {token}"))]);
            h.insert(
                HeaderName::from_static("accept"),
                HeaderValue::from_static("application/json"),
            );
            return Ok(h);
        }
        let mut h = HeaderMap::new();
        h.insert(HeaderName::from_static("accept"), HeaderValue::from_static("application/json"));
        h.insert(HeaderName::from_static("nk"), HeaderValue::from_static("NT"));
        h.insert(
            HeaderName::from_static("origin"),
            HeaderValue::from_str(&self.connect).unwrap(),
        );
        h.insert(
            HeaderName::from_static("referer"),
            HeaderValue::from_str(&format!("{}/modern/", self.connect)).unwrap(),
        );
        h.insert(
            HeaderName::from_static("di-backend"),
            HeaderValue::from_str(&format!("connectapi.{}", self.domain)).unwrap(),
        );
        h.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_str(&format!("JWT_WEB={}", self.jwt_web.as_ref().unwrap())).unwrap(),
        );
        Ok(h)
    }

    async fn run_request(
        &mut self,
        method: Method,
        path: &str,
        json_body: Option<&Value>,
    ) -> Result<wreq::Response> {
        if self.is_authenticated() && self.token_expires_soon() {
            let _ = self.refresh_session().await;
        }

        let url = format!("{}/{}", self.connectapi, path.trim_start_matches('/'));
        let headers = self.api_headers()?;

        let send = |c: &Client, h: HeaderMap| {
            let mut req = c.request(method.clone(), &url).headers(h);
            if let Some(b) = json_body {
                req = req.json(b);
            }
            req.send()
        };

        let mut resp = send(&self.api_client, headers.clone()).await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            let _ = self.refresh_session().await;
            let headers = self.api_headers()?;
            resp = send(&self.api_client, headers).await?;
        }

        if resp.status().as_u16() >= 400 {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| {
                    v.get("message")
                        .or_else(|| v.get("content"))
                        .and_then(|m| m.as_str().map(str::to_string))
                })
                .unwrap_or(text);
            let full = format!("API Error {status} - {msg}");
            return Err(if status == StatusCode::NOT_FOUND {
                GarminError::NotFound(full)
            } else {
                GarminError::Connection(full)
            });
        }

        Ok(resp)
    }

    pub async fn connectapi(&mut self, path: &str, body: Option<&Value>) -> Result<Value> {
        let resp = self.run_request(Method::GET, path, body).await?;
        Ok(resp.json().await?)
    }

    pub async fn get(&mut self, path: &str) -> Result<Value> {
        self.connectapi(path, None).await
    }

    pub async fn post(&mut self, path: &str, body: &Value) -> Result<Value> {
        let resp = self.run_request(Method::POST, path, Some(body)).await?;
        Ok(resp.json().await.unwrap_or(Value::Null))
    }

    pub async fn put(&mut self, path: &str, body: &Value) -> Result<Value> {
        let resp = self.run_request(Method::PUT, path, Some(body)).await?;
        Ok(resp.json().await.unwrap_or(Value::Null))
    }

    pub async fn delete(&mut self, path: &str) -> Result<Value> {
        let resp = self.run_request(Method::DELETE, path, None).await?;
        Ok(resp.json().await.unwrap_or(Value::Null))
    }

    pub async fn download(&mut self, path: &str) -> Result<Vec<u8>> {
        let resp = self.run_request(Method::GET, path, None).await?;
        Ok(resp.bytes().await?.to_vec())
    }
}

fn token_file_path(path: &Path) -> PathBuf {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if path.is_dir() || !is_json {
        path.join("garmin_tokens.json")
    } else {
        path.to_path_buf()
    }
}

fn extract_client_id_from_jwt(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.trim_end_matches('='))
        .ok()?;
    let json: Value = serde_json::from_slice(&payload).ok()?;
    json["client_id"].as_str().map(str::to_string)
}

fn jwt_exp(token: &str) -> Option<i64> {
    let payload_b64 = token.split('.').nth(1)?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.trim_end_matches('='))
        .ok()?;
    let json: Value = serde_json::from_slice(&payload).ok()?;
    json["exp"].as_i64()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a syntactically valid (unsigned) JWT with the given payload,
    /// mirroring what `extract_client_id_from_jwt`/`jwt_exp` parse out of
    /// real Garmin DI tokens.
    fn fake_jwt(payload: &Value) -> String {
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        format!("header.{payload_b64}.signature")
    }

    // ---------------------------------------------------------------- //
    //  token_file_path                                                  //
    // ---------------------------------------------------------------- //

    #[test]
    fn token_file_path_keeps_explicit_json_file_path_unchanged() {
        let path = Path::new("/tmp/definitely-does-not-exist-xyz/tokens.json");
        assert_eq!(token_file_path(path), path);
    }

    #[test]
    fn token_file_path_appends_default_filename_for_directories() {
        let dir = std::env::temp_dir();
        assert_eq!(token_file_path(&dir), dir.join("garmin_tokens.json"));
    }

    #[test]
    fn token_file_path_appends_default_filename_for_non_json_paths() {
        let path = Path::new("/tmp/definitely-does-not-exist-xyz/tokens");
        assert_eq!(token_file_path(path), path.join("garmin_tokens.json"));
    }

    // ---------------------------------------------------------------- //
    //  JWT parsing                                                      //
    // ---------------------------------------------------------------- //

    #[test]
    fn extract_client_id_from_jwt_reads_the_claim() {
        let token = fake_jwt(&serde_json::json!({ "client_id": "GARMIN_CONNECT_MOBILE_ANDROID_DI" }));
        assert_eq!(
            extract_client_id_from_jwt(&token),
            Some("GARMIN_CONNECT_MOBILE_ANDROID_DI".to_string())
        );
    }

    #[test]
    fn extract_client_id_from_jwt_returns_none_for_malformed_token() {
        assert_eq!(extract_client_id_from_jwt("not-a-jwt"), None);
        assert_eq!(extract_client_id_from_jwt(""), None);
    }

    #[test]
    fn jwt_exp_reads_the_claim() {
        let token = fake_jwt(&serde_json::json!({ "exp": 1_800_000_000_i64 }));
        assert_eq!(jwt_exp(&token), Some(1_800_000_000));
    }

    #[test]
    fn jwt_exp_returns_none_when_claim_missing() {
        let token = fake_jwt(&serde_json::json!({ "client_id": "x" }));
        assert_eq!(jwt_exp(&token), None);
    }

    // ---------------------------------------------------------------- //
    //  MfaFlow                                                          //
    // ---------------------------------------------------------------- //

    #[test]
    fn mfa_flow_path_segment_matches_garmin_endpoints() {
        assert_eq!(MfaFlow::Ios.path_segment(), "mobile");
        assert_eq!(MfaFlow::Portal.path_segment(), "portal");
    }

    // ---------------------------------------------------------------- //
    //  GarminClient: token expiry and persistence                       //
    // ---------------------------------------------------------------- //

    #[test]
    fn token_expires_soon_is_false_without_a_di_token() {
        let client = GarminClient::new("garmin.com").unwrap();
        assert!(!client.token_expires_soon());
    }

    #[test]
    fn token_expires_soon_is_true_for_an_already_expired_token() {
        let mut client = GarminClient::new("garmin.com").unwrap();
        client.di_token = Some(fake_jwt(&serde_json::json!({ "exp": 0 })));
        assert!(client.token_expires_soon());
    }

    #[test]
    fn token_expires_soon_is_true_within_the_15_minute_safety_margin() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut client = GarminClient::new("garmin.com").unwrap();
        client.di_token = Some(fake_jwt(&serde_json::json!({ "exp": now + 60 })));
        assert!(client.token_expires_soon());
    }

    #[test]
    fn token_expires_soon_is_false_far_in_the_future() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut client = GarminClient::new("garmin.com").unwrap();
        client.di_token = Some(fake_jwt(&serde_json::json!({ "exp": now + 3600 })));
        assert!(!client.token_expires_soon());
    }

    #[test]
    fn dumps_then_loads_round_trips_the_native_tokens() {
        let mut client = GarminClient::new("garmin.com").unwrap();
        client.di_token = Some("access-token".to_string());
        client.di_refresh_token = Some("refresh-token".to_string());
        client.di_client_id = Some("GARMIN_CONNECT_MOBILE_ANDROID_DI".to_string());

        let dumped = client.dumps().unwrap();

        let mut restored = GarminClient::new("garmin.com").unwrap();
        restored.loads(&dumped).unwrap();

        assert_eq!(restored.di_token, client.di_token);
        assert_eq!(restored.di_refresh_token, client.di_refresh_token);
        assert_eq!(restored.di_client_id, client.di_client_id);
        assert!(restored.is_authenticated());
    }

    #[test]
    fn loads_rejects_a_token_store_with_no_usable_tokens() {
        let mut client = GarminClient::new("garmin.com").unwrap();
        let empty = serde_json::to_string(&TokenData::default()).unwrap();
        let err = client.loads(&empty).unwrap_err();
        assert!(matches!(err, GarminError::Authentication(_)));
    }

    #[test]
    fn loads_rejects_invalid_json() {
        let mut client = GarminClient::new("garmin.com").unwrap();
        let err = client.loads("not json").unwrap_err();
        assert!(matches!(err, GarminError::Json(_)));
    }

    #[test]
    fn is_authenticated_reflects_either_token_kind() {
        let mut client = GarminClient::new("garmin.com").unwrap();
        assert!(!client.is_authenticated());

        client.di_token = Some("access-token".to_string());
        assert!(client.is_authenticated());

        client.clear_auth_state();
        assert!(!client.is_authenticated());

        client.jwt_web = Some("jwt".to_string());
        assert!(client.is_authenticated());
    }
}
