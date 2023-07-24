#![allow(non_snake_case)]

use std::collections::{HashMap, HashSet};

use http::response::Response;
use base64::engine::Engine;
use serde_json::json;

mod error;

pub use crate::error::Error;

static BASE64_NO_PAD: &base64::engine::general_purpose::GeneralPurpose =
    &base64::engine::general_purpose::STANDARD_NO_PAD;

pub trait DataSource
{
    fn verifyClient(&self, client_id: &str, redirect_uri: &str) -> bool;
    fn verifyClientSecret(&self, client_id: &str, client_secret: &str,
                          redirect_uri: &str) -> bool;
    fn verifyUser(&self, username: &str, password: &str) -> bool;
    fn createSession(&self, username: &str, client_id: &str, token: &str,
                     expire: time::OffsetDateTime) -> Result<(), Error>;
}

pub struct AuthServer
{
    auth_url: String,
    /// A collection of on-going auth sessions
    auth_sessions: HashSet<String>,
    /// A map from auth code to client ID
    auth_codes: HashMap<String, String>,
    data_source: Box<dyn DataSource + 'static>,
    access_token_ttl_sec: u64,
}

impl AuthServer
{
    pub fn new<T: DataSource + 'static>(
        auth_url: &str, data_source: T, access_token_ttl_sec: u64) -> Self
    {
        Self {
            auth_url: auth_url.to_owned(),
            auth_sessions: HashSet::new(),
            auth_codes: HashMap::new(),
            data_source: Box::new(data_source),
            access_token_ttl_sec,
        }
    }

    pub fn initAuthorization(&mut self, client_id: &str, redirect_uri: &str,
                             state: &str) -> Result<Response<()>, Error>
    {
        if self.data_source.verifyClient(client_id, redirect_uri)
        {
            self.auth_sessions.insert(state.to_owned());
            let url = format!("{}?state={}", self.auth_url,
                              urlencoding::encode(state));
            Ok(Response::builder().status(302).header("Location", url).body(())
               .unwrap())
        }
        else
        {
            Err(http_error!(401, "Invalid client"))
        }
    }

    fn generateAuthCode() -> String
    {
        let bytes: [u8; 16] = rand::random();
        BASE64_NO_PAD.encode(&bytes)
    }

    fn generateToken() -> String
    {
        let bytes: [u8; 16] = rand::random();
        BASE64_NO_PAD.encode(&bytes)
    }

    pub fn verifyUser(&mut self, username: &str, password: &str, state: &str) ->
        Result<Response<()>, Error>
    {
        if !self.data_source.verifyUser(username, password)
        {
            return Err(http_error!(401, "Invalid user"));
        }
        if !self.auth_sessions.contains(state)
        {
            return Err(http_error!(401, "Invalid session"));
        }
        let code = Self::generateAuthCode();
        let url = format!("{}?code={}&state={}", self.auth_url, code,
                          urlencoding::encode(state));
        self.auth_sessions.remove(state);
        self.auth_codes.insert(code, username.to_owned());
        Ok(Response::builder().status(302).header("Location", url).body(())
           .unwrap())
    }

    pub fn grant(&self, grant_type: &str, client_id: &str, client_secret: &str,
                 redirect_uri: &str, auth_code: &str) ->
        Result<Response<Vec<u8>>, Error>
    {
        if grant_type != "authorization_code"
        {
            return Err(http_error!(401, "Unsupported grant type"));
        }

        let user = if let Some(name) = self.auth_codes.get(auth_code)
        {
            name
        }
        else
        {
            return Err(http_error!(401, "Invalid authorization code"));
        };

        if !self.data_source.verifyClientSecret(
            client_id, client_secret, redirect_uri)
        {
            return Err(http_error!(401, "Invalid client"));
        }

        let token = Self::generateToken();
        self.data_source.createSession(
            user, client_id, &token, time::OffsetDateTime::now_utc() +
                time::Duration::seconds(self.access_token_ttl_sec as i64))
            .map_err(|e| http_error!(500, "Failed to create session: {}", e))?;

        let data = json!({
            "token_type": "Bearer",
            "expires_in": self.access_token_ttl_sec,
            "access_token": token,
            // "refresh_token":
        });

        Ok(Response::builder().status(200)
           .header("Content-Type", "application/json; charset=utf-8")
           .body(serde_json::to_vec(&data).map_err(
               |_| http_error!(500, "Failed to serialize response"))?)
           .unwrap())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
}
