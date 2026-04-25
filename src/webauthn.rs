use anyhow::Context as _;
use futures::StreamExt as _;
use webauthn_authenticator_rs::{
    ctap2::CtapAuthenticator,
    transport::{AnyTransport, TokenEvent, Transport as _},
    types::{CableRequestType, CableState, EnrollSampleStatus},
    ui::UiCallback,
    AuthenticatorBackend as _,
};
use webauthn_rs_proto::PublicKeyCredentialRequestOptions;

use crate::locked::Password;

pub async fn webauthn(
    challenge: PublicKeyCredentialRequestOptions,
    pin: &str,
) -> anyhow::Result<Password> {
    let transport = AnyTransport::new()
        .await
        .context("failed to set up webauthn transport")?;

    let ui = Pinentry {
        pin: pin.to_string(),
    };

    let mut events = transport
        .watch()
        .await
        .context("failed to watch webauthn transport")?;

    let mut authenticator = loop {
        match events.next().await {
            Some(TokenEvent::Added(token)) => {
                if let Some(auth) = CtapAuthenticator::new(token, &ui).await {
                    break auth;
                }
            }
            Some(TokenEvent::EnumerationComplete) => {
                log::info!(
                    "rbw: connect a FIDO2 security key to continue"
                );
            }
            Some(TokenEvent::Removed(_)) => {}
            None => {
                anyhow::bail!(
                    "webauthn transport closed before a token connected"
                );
            }
        }
    };

    let origin = crate::config::Config::load_async()
        .await
        .context("failed to load rbw config")?
        .ui_url();
    let origin = reqwest::Url::parse(&origin)
        .context("failed to parse vault url as URL")?;

    let result = authenticator
        .perform_auth(origin, challenge, 60_000)
        .map_err(|e| {
            anyhow::anyhow!("webauthn authentication failed: {e:?}")
        })?;

    let out = serde_json::to_string(&BitwardenAssertion::from(result))
        .context("failed to serialize webauthn assertion")?;

    let mut buf = crate::locked::Vec::new();
    buf.extend(out.as_bytes().iter().copied());
    Ok(Password::new(buf))
}

// Bitwarden's server expects a slightly different shape than what
// webauthn-rs-proto serializes by default: the response field is camelCase
// `clientDataJson` rather than the W3C-spec `clientDataJSON`, and the
// extensions object must use a non-nullable `appid: bool`. We build a
// dedicated wire type instead of munging the JSON.
#[derive(serde::Serialize)]
struct BitwardenAssertion {
    id: String,
    #[serde(rename = "rawId")]
    raw_id: base64urlsafedata::Base64UrlSafeData,
    response: BitwardenAssertionResponse,
    extensions: BitwardenAssertionExtensions,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenAssertionResponse {
    authenticator_data: base64urlsafedata::Base64UrlSafeData,
    client_data_json: base64urlsafedata::Base64UrlSafeData,
    signature: base64urlsafedata::Base64UrlSafeData,
    user_handle: Option<base64urlsafedata::Base64UrlSafeData>,
}

#[derive(serde::Serialize)]
struct BitwardenAssertionExtensions {
    appid: bool,
}

impl From<webauthn_rs_proto::PublicKeyCredential> for BitwardenAssertion {
    fn from(c: webauthn_rs_proto::PublicKeyCredential) -> Self {
        Self {
            id: c.id,
            raw_id: c.raw_id,
            response: BitwardenAssertionResponse {
                authenticator_data: c.response.authenticator_data,
                client_data_json: c.response.client_data_json,
                signature: c.response.signature,
                user_handle: c.response.user_handle,
            },
            extensions: BitwardenAssertionExtensions {
                appid: c.extensions.appid.unwrap_or(false),
            },
            type_: c.type_,
        }
    }
}

#[derive(Debug)]
struct Pinentry {
    pin: String,
}

impl UiCallback for Pinentry {
    fn request_pin(&self) -> Option<String> {
        Some(self.pin.clone())
    }

    fn request_touch(&self) {
        log::debug!("webauthn: waiting for user presence (touch the key)");
    }

    fn fingerprint_enrollment_feedback(
        &self,
        _remaining_samples: u32,
        _feedback: Option<EnrollSampleStatus>,
    ) {
        log::warn!("webauthn: fingerprint_enrollment_feedback unimplemented");
    }

    fn cable_qr_code(&self, _request_type: CableRequestType, _url: String) {
        log::warn!("webauthn: cable_qr_code unimplemented");
    }

    fn dismiss_qr_code(&self) {
        log::warn!("webauthn: dismiss_qr_code unimplemented");
    }

    fn cable_status_update(&self, _state: CableState) {
        log::warn!("webauthn: cable_status_update unimplemented");
    }

    fn processing(&self) {
        log::debug!("webauthn: processing...");
    }
}
