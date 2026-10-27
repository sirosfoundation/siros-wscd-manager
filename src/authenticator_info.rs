//! Read-only description of a CTAP2 authenticator, for a host to show the
//! user BEFORE enrolment ("this key has no PIN yet", "5 PIN attempts left",
//! "this key cannot be used here").
//!
//! Sends `authenticatorGetInfo` (0x04) and, only when a PIN is set,
//! `authenticatorClientPIN` `getPinRetries` (0x06 / 0x01, which consumes no
//! retry). It never obtains a PIN, never sends `setPIN`, never requests a
//! `pinUvAuthToken` - and takes no `AuthCallback`, so it cannot prompt.

use std::collections::BTreeMap;

use ciborium::Value;

use crate::callbacks::Ctap2Transport;
use crate::ctap2_client_pin::{
    get_pin_retries, PinState, PinUvAuthProtocol, DEFAULT_MIN_PIN_LENGTH,
};
use crate::error::{Result, WscdError};
use crate::preview_sign_protocol::split_status;

/// The extension identifier the previewSign plugin's makeCredential needs.
pub const PREVIEW_SIGN_EXTENSION: &str = "previewSign";

/// Whether this authenticator can be enrolled by the previewSign plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrolmentSuitability {
    Suitable,
    Unsuitable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorInfo {
    pub versions: Vec<String>,
    pub aaguid: [u8; 16],
    pub client_pin: PinState,
    /// getInfo `minPINLength` (4 when absent).
    pub min_pin_length: u32,
    /// getInfo `forcePINChange` (false when absent).
    pub force_pin_change: bool,
    /// Remaining PIN attempts; `Some` only when a PIN is set.
    pub pin_retries: Option<u32>,
    pub pin_uv_auth_protocols: Vec<u32>,
    pub extensions: Vec<String>,
    pub options: BTreeMap<String, bool>,
    pub enrolment_suitability: EnrolmentSuitability,
}

fn get(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(key))
        .map(|(_, v)| v)
}

fn text_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_text().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a getInfo CBOR body (without the status byte). Suitability and
/// retries are filled in by the caller.
fn parse_get_info(body: &[u8]) -> Result<AuthenticatorInfo> {
    let value: Value = ciborium::de::from_reader(body)
        .map_err(|e| WscdError::Crypto(format!("invalid getInfo CBOR: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| WscdError::Crypto("getInfo response is not a CBOR map".into()))?;

    let aaguid: [u8; 16] = get(map, 3)
        .and_then(|v| v.as_bytes())
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or_else(|| WscdError::Crypto("getInfo aaguid missing or not 16 bytes".into()))?;

    let options: BTreeMap<String, bool> = get(map, 4)
        .and_then(|v| v.as_map())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.as_text()?.to_string(), v.as_bool()?)))
                .collect()
        })
        .unwrap_or_default();
    let client_pin = match options.get("clientPin") {
        Some(true) => PinState::Set,
        Some(false) => PinState::NotSet,
        None => PinState::Unsupported,
    };

    let pin_uv_auth_protocols = get(map, 6)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| u32::try_from(i128::from(v.as_integer()?)).ok())
                .collect()
        })
        .unwrap_or_default();

    Ok(AuthenticatorInfo {
        versions: text_list(get(map, 1)),
        aaguid,
        client_pin,
        min_pin_length: get(map, 0x0D)
            .and_then(|v| v.as_integer())
            .and_then(|i| u32::try_from(i128::from(i)).ok())
            .unwrap_or(DEFAULT_MIN_PIN_LENGTH),
        force_pin_change: get(map, 0x0C).and_then(|v| v.as_bool()).unwrap_or(false),
        pin_retries: None,
        pin_uv_auth_protocols,
        extensions: text_list(get(map, 2)),
        options,
        enrolment_suitability: EnrolmentSuitability::Suitable,
    })
}

/// What the previewSign plugin's `makeCredential` ceremony needs, judged
/// from getInfo alone:
/// - the `previewSign` extension (without it the authenticator creates the
///   base credential but silently omits the generated key - see
///   `ctap2_client_pin` module docs);
/// - on a raw transport (`performs_user_verification == false`), the plugin
///   obtains a `pinUvAuthToken` from a PIN, which needs ClientPin support
///   (`clientPin` option present), no pending forced PIN change, and a
///   PinUvAuthProtocol this crate implements (1 or 2; absent defaults to 1,
///   as the token exchange assumes). A transport that performs user
///   verification itself (a browser) does none of that.
fn suitability(info: &AuthenticatorInfo, performs_uv: bool) -> EnrolmentSuitability {
    let no = |reason: &str| EnrolmentSuitability::Unsuitable {
        reason: reason.to_string(),
    };
    if !info.extensions.iter().any(|e| e == PREVIEW_SIGN_EXTENSION) {
        return no("the authenticator does not advertise the previewSign extension");
    }
    if performs_uv {
        return EnrolmentSuitability::Suitable;
    }
    if info.client_pin == PinState::Unsupported {
        return no("the authenticator has no PIN support (clientPin option absent), but enrolment needs PIN user verification");
    }
    if info.force_pin_change {
        return no("the authenticator requires its PIN to be changed before it can be used");
    }
    if !info.pin_uv_auth_protocols.is_empty()
        && !info
            .pin_uv_auth_protocols
            .iter()
            .any(|p| PinUvAuthProtocol::from_int(i64::from(*p)).is_some())
    {
        return no(
            "the authenticator supports no PinUvAuthProtocol this library implements (1 or 2)",
        );
    }
    EnrolmentSuitability::Suitable
}

/// Describe the authenticator behind `transport`. Read-only; see the module
/// docs. Uses the given transport as is - it never opens or closes a
/// connection itself, so an already-open one is reused.
pub async fn describe_authenticator(transport: &dyn Ctap2Transport) -> Result<AuthenticatorInfo> {
    let response = transport.ctap2_send_command(&[0x04]).await?;
    let mut info = parse_get_info(split_status(&response)?)?;
    if info.client_pin == PinState::Set {
        let protocol = info
            .pin_uv_auth_protocols
            .iter()
            .find_map(|p| PinUvAuthProtocol::from_int(i64::from(*p)))
            .unwrap_or(PinUvAuthProtocol::One);
        info.pin_retries = Some(get_pin_retries(transport, protocol).await?);
    }
    info.enrolment_suitability = suitability(&info, transport.performs_user_verification());
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        extensions: Vec<&'static str>,
        client_pin: Option<bool>,
        force_pin_change: Option<bool>,
        min_pin_length: Option<u32>,
        protocols: Option<Vec<i64>>,
        retries: u32,
        performs_uv: bool,
        log: Mutex<Vec<Vec<u8>>>,
    }

    impl Fake {
        fn yubikey(client_pin: Option<bool>) -> Self {
            Self {
                extensions: vec!["previewSign", "hmac-secret"],
                client_pin,
                force_pin_change: None,
                min_pin_length: None,
                protocols: Some(vec![2, 1]),
                retries: 8,
                performs_uv: false,
                log: Mutex::new(vec![]),
            }
        }
        /// (command byte, ClientPin subCommand) per command received.
        fn seen(&self) -> Vec<(u8, Option<i128>)> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|c| {
                    let sub = (c[0] == 0x06).then(|| {
                        let v: Value = ciborium::de::from_reader(&c[1..]).unwrap();
                        get(v.as_map().unwrap(), 2)
                            .unwrap()
                            .as_integer()
                            .map(i128::from)
                            .unwrap()
                    });
                    (c[0], sub)
                })
                .collect()
        }
    }

    fn cbor(v: &Value) -> Vec<u8> {
        let mut out = vec![0u8];
        ciborium::ser::into_writer(v, &mut out).unwrap();
        out
    }

    #[async_trait::async_trait]
    impl Ctap2Transport for Fake {
        async fn ctap2_send_command(&self, command: &[u8]) -> Result<Vec<u8>> {
            self.log.lock().unwrap().push(command.to_vec());
            let int = |i: i64| Value::Integer(i.into());
            match command[0] {
                0x04 => {
                    let mut opts = vec![(Value::Text("rk".into()), Value::Bool(true))];
                    if let Some(cp) = self.client_pin {
                        opts.push((Value::Text("clientPin".into()), Value::Bool(cp)));
                    }
                    let mut m = vec![
                        (
                            int(1),
                            Value::Array(vec![
                                Value::Text("FIDO_2_1".into()),
                                Value::Text("FIDO_2_0".into()),
                            ]),
                        ),
                        (
                            int(2),
                            Value::Array(
                                self.extensions
                                    .iter()
                                    .map(|e| Value::Text((*e).into()))
                                    .collect(),
                            ),
                        ),
                        (int(3), Value::Bytes((0u8..16).collect())),
                        (int(4), Value::Map(opts)),
                    ];
                    if let Some(p) = &self.protocols {
                        m.push((int(6), Value::Array(p.iter().map(|x| int(*x)).collect())));
                    }
                    if let Some(f) = self.force_pin_change {
                        m.push((int(0x0C), Value::Bool(f)));
                    }
                    if let Some(l) = self.min_pin_length {
                        m.push((int(0x0D), int(l as i64)));
                    }
                    Ok(cbor(&Value::Map(m)))
                }
                0x06 => {
                    let v: Value = ciborium::de::from_reader(&command[1..]).unwrap();
                    assert_eq!(
                        get(v.as_map().unwrap(), 2)
                            .unwrap()
                            .as_integer()
                            .map(i128::from),
                        Some(1),
                        "only getPinRetries is allowed"
                    );
                    Ok(cbor(&Value::Map(vec![(int(3), int(self.retries as i64))])))
                }
                other => panic!("describe must not send command 0x{other:02x}"),
            }
        }
        fn performs_user_verification(&self) -> bool {
            self.performs_uv
        }
    }

    #[tokio::test]
    async fn pin_set_reports_retries_and_queries_them_once() {
        let t = Fake::yubikey(Some(true));
        let i = describe_authenticator(&t).await.unwrap();
        assert_eq!(i.client_pin, PinState::Set);
        assert_eq!(i.pin_retries, Some(8));
        assert_eq!(i.aaguid, core::array::from_fn::<u8, 16, _>(|n| n as u8));
        assert_eq!(i.versions, ["FIDO_2_1", "FIDO_2_0"]);
        assert_eq!(i.pin_uv_auth_protocols, [2, 1]);
        assert_eq!(i.extensions, ["previewSign", "hmac-secret"]);
        assert_eq!(i.options.get("rk"), Some(&true));
        assert_eq!(i.min_pin_length, 4, "default when absent");
        assert!(!i.force_pin_change);
        assert_eq!(i.enrolment_suitability, EnrolmentSuitability::Suitable);
        // Exactly getInfo + getPinRetries: no keyAgreement(2)/setPIN(3)/token(9).
        assert_eq!(t.seen(), vec![(0x04, None), (0x06, Some(1))]);
    }

    #[tokio::test]
    async fn pin_not_set_does_not_query_retries() {
        let mut t = Fake::yubikey(Some(false));
        t.min_pin_length = Some(6);
        let i = describe_authenticator(&t).await.unwrap();
        assert_eq!(i.client_pin, PinState::NotSet);
        assert_eq!(i.pin_retries, None);
        assert_eq!(i.min_pin_length, 6);
        assert_eq!(i.enrolment_suitability, EnrolmentSuitability::Suitable);
        assert_eq!(t.seen(), vec![(0x04, None)], "no ClientPin command at all");
    }

    #[tokio::test]
    async fn client_pin_absent_is_unsupported_and_unsuitable_on_a_raw_transport() {
        let t = Fake::yubikey(None);
        let i = describe_authenticator(&t).await.unwrap();
        assert_eq!(i.client_pin, PinState::Unsupported);
        assert_eq!(i.pin_retries, None);
        assert!(matches!(
            i.enrolment_suitability,
            EnrolmentSuitability::Unsuitable { .. }
        ));
        assert_eq!(t.seen(), vec![(0x04, None)]);

        // A transport that performs user verification itself needs no PIN.
        let mut t = Fake::yubikey(None);
        t.performs_uv = true;
        let i = describe_authenticator(&t).await.unwrap();
        assert_eq!(i.enrolment_suitability, EnrolmentSuitability::Suitable);
    }

    #[tokio::test]
    async fn force_pin_change_is_reported_and_blocks_enrolment() {
        let mut t = Fake::yubikey(Some(true));
        t.force_pin_change = Some(true);
        let i = describe_authenticator(&t).await.unwrap();
        assert!(i.force_pin_change);
        assert!(matches!(
            i.enrolment_suitability,
            EnrolmentSuitability::Unsuitable { ref reason } if reason.contains("changed")
        ));
    }

    #[tokio::test]
    async fn missing_preview_sign_or_no_usable_protocol_is_unsuitable() {
        let mut t = Fake::yubikey(Some(true));
        t.extensions = vec!["hmac-secret"];
        let i = describe_authenticator(&t).await.unwrap();
        assert!(matches!(
            i.enrolment_suitability,
            EnrolmentSuitability::Unsuitable { ref reason } if reason.contains("previewSign")
        ));

        let mut t = Fake::yubikey(Some(true));
        t.protocols = Some(vec![3]);
        let i = describe_authenticator(&t).await.unwrap();
        assert!(matches!(
            i.enrolment_suitability,
            EnrolmentSuitability::Unsuitable { ref reason } if reason.contains("PinUvAuthProtocol")
        ));
    }

    #[tokio::test]
    async fn malformed_aaguid_is_an_error_not_a_guess() {
        struct Bad;
        #[async_trait::async_trait]
        impl Ctap2Transport for Bad {
            async fn ctap2_send_command(&self, _: &[u8]) -> Result<Vec<u8>> {
                Ok(cbor(&Value::Map(vec![(
                    Value::Integer(3.into()),
                    Value::Bytes(vec![0; 15]),
                )])))
            }
        }
        assert!(describe_authenticator(&Bad).await.is_err());
    }
}
