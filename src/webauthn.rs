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
                eprintln!("rbw: connect a FIDO2 security key to continue...");
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

    // Bitwarden's server expects a slightly different shape than the
    // webauthn-rs default serialization: `appid` must be `false` (not null)
    // and the credential field is camelCase `clientDataJson` rather than
    // `clientDataJSON`. See doy/rbw#116 for context.
    let out = serde_json::to_string(&result)
        .context("failed to serialize webauthn assertion")?
        .replace("\"appid\":null,\"hmac_get_secret\":null", "\"appid\":false")
        .replace("clientDataJSON", "clientDataJson");

    let mut buf = crate::locked::Vec::new();
    buf.extend(out.as_bytes().iter().copied());
    Ok(Password::new(buf))
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
        eprintln!("rbw: touch your security key to continue...");
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
