//! Browser WebAuthn `previewSign` transport for the FIDO2 rawSign plugin.
//!
//! [`PreviewSignPlugin`](crate::plugins::preview_sign::PreviewSignPlugin) is
//! transport-agnostic — it calls [`Ctap2Transport`] and doesn't know or care
//! whether the host relays those calls over native CTAP2 (BLE/NFC/USB) or,
//! as here, through the browser's WebAuthn API. This is the browser
//! implementation: it calls `navigator.credentials.create()`/`.get()` with
//! the (non-standard, YubiKey firmware ≥5.8) `previewSign` extension
//! ("WebAuthn sign extension" draft v4:
//! <https://yubicolabs.github.io/webauthn-sign-extension/4/>) via `web-sys`,
//! since `web-sys`'s typed WebAuthn bindings only cover the standard
//! extensions — `previewSign` is set/read via raw `js_sys::Reflect` calls on
//! top of the typed option objects.
//!
//! The extension's JS field names (`generateKey`/`signByCredential`/
//! `generatedKey`/`keyHandle`/`publicKey`/`attestationObject`) and where
//! each value actually surfaces (`generatedKey` via the standard
//! `getClientExtensionResults()`; the assertion `signature` only inside raw
//! `authenticatorData`, via [`preview_sign_protocol::extract_previewsign_signature`])
//! are taken from a real browser integration
//! (wallet-frontend PR #22's `sign-extension.ts`), not just the spec text —
//! that integration is the strongest evidence available that this shape
//! actually works against real hardware.
//!
//! `rp_id`: [`Ctap2Transport`]'s methods take an `rp_id` parameter meant for
//! CTAP2 authenticators generically (the native `PreviewSignPlugin` passes
//! a synthetic constant, "siros.wscd.preview-sign", that has no meaning to
//! a browser). The browser's WebAuthn API requires `rp.id` to be the
//! current page's actual hostname (or a registrable parent domain) — it
//! will throw a `SecurityError` otherwise — so this transport ignores the
//! passed `rp_id` and substitutes `window.location().hostname()`.

#![cfg(feature = "wasm")]

use js_sys::{Array, Object, Reflect, Uint8Array};
use send_wrapper::SendWrapper;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{
    AuthenticationExtensionsClientInputs, AuthenticatorAssertionResponse,
    CredentialCreationOptions, CredentialRequestOptions, PublicKeyCredential,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity,
};

use crate::callbacks::Ctap2Transport;
use crate::error::{Result, WscdError};
use crate::preview_sign_protocol::{
    self, GenerateKeyInput, GeneratedKey, MakeCredentialResult, SignInput, SignResult,
};

/// WebAuthn `previewSign` implementation of [`Ctap2Transport`], for
/// registering the FIDO2 rawSign plugin in a browser.
pub struct WasmFido2Transport;

fn js_err(context: &str, err: JsValue) -> WscdError {
    let msg = err
        .as_string()
        .or_else(|| {
            Reflect::get(&err, &JsValue::from_str("message"))
                .ok()
                .and_then(|m| m.as_string())
        })
        .unwrap_or_else(|| format!("{err:?}"));
    // WebAuthn signals user cancellation / no matching authenticator /
    // timeout as a DOMException named "NotAllowedError" — map that
    // specifically so callers can distinguish "user declined" from a
    // genuine transport failure.
    let is_not_allowed = Reflect::get(&err, &JsValue::from_str("name"))
        .ok()
        .and_then(|n| n.as_string())
        .map(|n| n == "NotAllowedError")
        .unwrap_or(false);
    if is_not_allowed {
        WscdError::AuthCancelled
    } else {
        WscdError::Callback(format!("{context}: {msg}"))
    }
}

fn hostname() -> Result<String> {
    web_sys::window()
        .ok_or_else(|| WscdError::Callback("no window (not running in a browser)".into()))?
        .location()
        .hostname()
        .map_err(|e| js_err("read location.hostname", e))
}

async fn credentials() -> Result<web_sys::CredentialsContainer> {
    let window = web_sys::window()
        .ok_or_else(|| WscdError::Callback("no window (not running in a browser)".into()))?;
    Ok(window.navigator().credentials())
}

/// Set a property on a `web-sys` dictionary object that has no typed setter
/// (e.g. the non-standard `previewSign` extension) via raw `Reflect`.
fn set_extension(
    inputs: &AuthenticationExtensionsClientInputs,
    key: &str,
    value: &JsValue,
) -> Result<()> {
    Reflect::set(inputs.as_ref(), &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|e| js_err("set extension property", e))
}

fn reflect_set(obj: &Object, key: &str, value: &JsValue) -> Result<()> {
    Reflect::set(obj, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|e| js_err("build previewSign extension object", e))
}

fn reflect_get_bytes(obj: &JsValue, key: &str) -> Result<Vec<u8>> {
    let value = Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|e| js_err(&format!("read previewSign.{key}"), e))?;
    if value.is_undefined() || value.is_null() {
        return Err(WscdError::Callback(format!(
            "previewSign result missing field {key}"
        )));
    }
    Ok(Uint8Array::new(&value).to_vec())
}

/// Build `{ previewSign: { generateKey: { algorithms } } }` on `extensions`.
fn set_generate_key_extension(
    extensions: &AuthenticationExtensionsClientInputs,
    algorithms: &[i64],
) -> Result<()> {
    let algorithms_array: Array = algorithms
        .iter()
        .map(|alg| JsValue::from(*alg as i32))
        .collect();
    let generate_key = Object::new();
    reflect_set(&generate_key, "algorithms", &algorithms_array.into())?;
    let preview_sign = Object::new();
    reflect_set(&preview_sign, "generateKey", &generate_key.into())?;
    set_extension(extensions, "previewSign", &preview_sign.into())
}

/// Build `{ previewSign: { signByCredential: { [credentialId]: { keyHandle, tbs, additionalArgs? } } } }`
/// on `extensions`. The map key is the base64url-encoded WebAuthn
/// credential ID, per the sign extension spec.
fn set_sign_by_credential_extension(
    extensions: &AuthenticationExtensionsClientInputs,
    credential_id: &[u8],
    sign: &SignInput,
) -> Result<()> {
    let sign_input = Object::new();
    reflect_set(
        &sign_input,
        "keyHandle",
        &Uint8Array::from(sign.key_handle.as_slice()).into(),
    )?;
    reflect_set(
        &sign_input,
        "tbs",
        &Uint8Array::from(sign.tbs.as_slice()).into(),
    )?;
    if let Some(args) = &sign.additional_args {
        reflect_set(
            &sign_input,
            "additionalArgs",
            &Uint8Array::from(args.as_slice()).into(),
        )?;
    }

    let sign_by_credential = Object::new();
    reflect_set(
        &sign_by_credential,
        &base64_url(credential_id),
        &sign_input.into(),
    )?;

    let preview_sign = Object::new();
    reflect_set(
        &preview_sign,
        "signByCredential",
        &sign_by_credential.into(),
    )?;
    set_extension(extensions, "previewSign", &preview_sign.into())
}

/// Read `previewSign.generatedKey` from a makeCredential response's
/// `getClientExtensionResults()` — the browser surfaces the generated
/// signing key's handle/public key/attestation object here directly,
/// pre-decoded into `ArrayBuffer`s (only `publicKey` remains COSE-CBOR-
/// encoded, decoded by [`preview_sign_protocol::decode_cose_ec2_public_key`]
/// later in [`crate::plugins::preview_sign::PreviewSignPlugin`]).
fn read_generated_key(extension_results: &JsValue) -> Result<GeneratedKey> {
    let preview_sign_result = Reflect::get(extension_results, &JsValue::from_str("previewSign"))
        .map_err(|e| js_err("read previewSign extension result", e))?;
    if preview_sign_result.is_undefined() {
        return Err(WscdError::Callback(
            "authenticator did not return a previewSign result — it may not support the sign extension"
                .into(),
        ));
    }
    let generated_key = Reflect::get(&preview_sign_result, &JsValue::from_str("generatedKey"))
        .map_err(|e| js_err("read previewSign.generatedKey", e))?;
    if generated_key.is_undefined() {
        return Err(WscdError::Callback(
            "authenticator did not generate a signing key (previewSign.generatedKey missing)"
                .into(),
        ));
    }

    let key_handle = reflect_get_bytes(&generated_key, "keyHandle")?;
    let public_key_cose = reflect_get_bytes(&generated_key, "publicKey")?;
    let attestation_object = reflect_get_bytes(&generated_key, "attestationObject")?;
    let algorithm = Reflect::get(&generated_key, &JsValue::from_str("algorithm"))
        .ok()
        .and_then(|v| v.as_f64())
        .ok_or_else(|| WscdError::Callback("previewSign.generatedKey missing algorithm".into()))?
        as i64;

    Ok(GeneratedKey {
        key_handle,
        public_key_cose,
        algorithm,
        attestation_object,
    })
}

fn base64_url(bytes: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(bytes)
}

#[async_trait::async_trait]
impl Ctap2Transport for WasmFido2Transport {
    /// The plugin talks raw CTAP2 command/response bytes uniformly across
    /// all transports (see [`crate::callbacks::Ctap2Transport`]'s doc
    /// comment) - this transport decodes the incoming command back into
    /// the structured fields it needs (via
    /// [`preview_sign_protocol::parse_make_credential_request`]/
    /// [`preview_sign_protocol::parse_get_assertion_request`]), makes the
    /// equivalent `navigator.credentials` call, then re-encodes a
    /// CTAP2-shaped response (via
    /// [`preview_sign_protocol::encode_make_credential_response`]/
    /// [`preview_sign_protocol::encode_get_assertion_response`]) so the
    /// plugin's own response parsing works identically regardless of
    /// transport.
    async fn ctap2_send_command(&self, command: &[u8]) -> Result<Vec<u8>> {
        match command.first() {
            Some(0x01) => {
                let req = preview_sign_protocol::parse_make_credential_request(command)?;
                let result = self
                    .make_credential_via_browser(
                        &req.user_id,
                        &req.client_data_hash,
                        &req.generate_key,
                    )
                    .await?;
                Ok(preview_sign_protocol::encode_make_credential_response(
                    &result,
                ))
            }
            Some(0x02) => {
                let req = preview_sign_protocol::parse_get_assertion_request(command)?;
                let result = self
                    .get_assertion_via_browser(&req.challenge, &req.credential_id, &req.sign)
                    .await?;
                Ok(preview_sign_protocol::encode_get_assertion_response(
                    &result,
                ))
            }
            other => Err(WscdError::Callback(format!(
                "unsupported CTAP2 command: {other:?}"
            ))),
        }
    }
}

impl WasmFido2Transport {
    async fn make_credential_via_browser(
        &self,
        user_id: &[u8],
        client_data_hash: &[u8],
        generate_key: &GenerateKeyInput,
    ) -> Result<MakeCredentialResult> {
        // JsFuture isn't Send, but async_trait's default macro expansion
        // requires the returned future to be Send (see the send_wrapper
        // dependency comment in Cargo.toml). Provably safe here: wasm32
        // has no real threads.
        SendWrapper::new(async move {
            let rp_id = hostname()?;

            let rp = PublicKeyCredentialRpEntity::new(&rp_id);
            rp.set_id(&rp_id);

            let user_id_array = Uint8Array::from(user_id);
            let user = PublicKeyCredentialUserEntity::new(
                "siros-wallet-instance",
                "SIROS Wallet",
                &user_id_array,
            );

            let pub_key_cred_params: Array = generate_key
                .algorithms
                .iter()
                .map(|alg| {
                    let p = PublicKeyCredentialParameters::new(
                        *alg as i32,
                        PublicKeyCredentialType::PublicKey,
                    );
                    JsValue::from(p)
                })
                .collect();

            let challenge = Uint8Array::from(client_data_hash);
            let opts = PublicKeyCredentialCreationOptions::new(
                &challenge,
                &pub_key_cred_params,
                &rp,
                &user,
            );

            let extensions = AuthenticationExtensionsClientInputs::new();
            set_generate_key_extension(&extensions, &generate_key.algorithms)?;
            opts.set_extensions(&extensions);

            let creation_opts = CredentialCreationOptions::new();
            creation_opts.set_public_key(&opts);

            let promise = credentials()
                .await?
                .create_with_options(&creation_opts)
                .map_err(|e| js_err("navigator.credentials.create", e))?;
            let credential = wasm_bindgen_futures::JsFuture::from(promise)
                .await
                .map_err(|e| js_err("navigator.credentials.create", e))?;
            let credential: PublicKeyCredential = credential.dyn_into().map_err(|_| {
                WscdError::Callback("create() did not return a PublicKeyCredential".into())
            })?;

            let credential_id = Uint8Array::new(&credential.raw_id()).to_vec();
            let generated_key = read_generated_key(&credential.get_client_extension_results())?;

            Ok(MakeCredentialResult {
                credential_id,
                generated_key,
            })
        })
        .await
    }

    async fn get_assertion_via_browser(
        &self,
        challenge: &[u8],
        credential_id: &[u8],
        sign: &SignInput,
    ) -> Result<SignResult> {
        SendWrapper::new(async move {
            let rp_id = hostname()?;

            let descriptor = PublicKeyCredentialDescriptor::new(
                &Uint8Array::from(credential_id),
                PublicKeyCredentialType::PublicKey,
            );
            let allow_credentials: Array = std::iter::once(JsValue::from(descriptor)).collect();

            let challenge_array = Uint8Array::from(challenge);
            let opts = PublicKeyCredentialRequestOptions::new(&challenge_array);
            opts.set_rp_id(&rp_id);
            opts.set_allow_credentials(&allow_credentials);

            let extensions = AuthenticationExtensionsClientInputs::new();
            set_sign_by_credential_extension(&extensions, credential_id, sign)?;
            opts.set_extensions(&extensions);

            let request_opts = CredentialRequestOptions::new();
            request_opts.set_public_key(&opts);

            let promise = credentials()
                .await?
                .get_with_options(&request_opts)
                .map_err(|e| js_err("navigator.credentials.get", e))?;
            let credential = wasm_bindgen_futures::JsFuture::from(promise)
                .await
                .map_err(|e| js_err("navigator.credentials.get", e))?;
            let credential: PublicKeyCredential = credential.dyn_into().map_err(|_| {
                WscdError::Callback("get() did not return a PublicKeyCredential".into())
            })?;

            // The rawSign result is NOT in getClientExtensionResults() for
            // assertions — unlike registration's generatedKey, the
            // signature is part of the *signed* authenticatorData
            // extensions, so it must be parsed out of the raw bytes.
            let response: AuthenticatorAssertionResponse =
                credential.response().dyn_into().map_err(|_| {
                    WscdError::Callback(
                        "credential.response is not an AuthenticatorAssertionResponse".into(),
                    )
                })?;
            let auth_data = Uint8Array::new(&response.authenticator_data()).to_vec();
            let signature = preview_sign_protocol::extract_previewsign_signature(&auth_data)?;

            Ok(SignResult { signature })
        })
        .await
    }
}
