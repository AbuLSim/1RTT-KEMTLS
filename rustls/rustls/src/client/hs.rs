use crate::{ALL_CIPHERSUITES, msgs::enums::{ContentType, HandshakeType, ExtensionType}};
use crate::msgs::enums::{Compression, ProtocolVersion, AlertDescription};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::base::Payload;
use crate::msgs::handshake::{HandshakePayload, HandshakeMessagePayload, ClientHelloPayload, ServerHelloPayload};
use crate::msgs::handshake::{SessionID, Random};
use crate::msgs::handshake::{ClientExtension, HasServerExtensions};
use crate::msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use crate::msgs::handshake::{ProtocolNameList, ConvertProtocolNameList};
use crate::msgs::handshake::HelloRetryRequest;
use crate::msgs::handshake::{CertificateStatusRequest, SCTList};
use crate::msgs::enums::{PSKKeyExchangeMode, ECPointFormat, SignatureAlgorithm};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::persist;
use crate::client::ClientSessionImpl;
use crate::session::SessionSecrets;
use crate::key_schedule::{KeyScheduleEarly, KeyScheduleHandshake, KeyScheduleNonSecret};
use crate::cipher;
use crate::suites;
use crate::verify;
use crate::rand;
use crate::ticketer;
#[cfg(feature = "logging")]
use crate::bs_debug;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::check::check_message;
use crate::error::TLSError;
#[cfg(feature = "quic")]
use crate::{
    quic,
    msgs::base::PayloadU16
};

use crate::client::common::{ServerCertDetails, HandshakeDetails};
use crate::client::common::{ClientHelloDetails, ReceivedTicketDetails};
use crate::client::{tls12, tls13};
use crate::hash_hs;

use log::warn;
use webpki;

use super::common::ClientAuthDetails;

pub type NextState = Box<dyn State + Send + Sync>;
pub type NextStateOrError = Result<NextState, TLSError>;

pub trait State {
    /// Each handle() implementation consumes a whole TLS message, and returns
    /// either an error or the next state.
    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError;

    fn export_keying_material(&self,
                              _output: &mut [u8],
                              _label: &[u8],
                              _context: Option<&[u8]>) -> Result<(), TLSError> {
        Err(TLSError::HandshakeNotComplete)
    }

    fn perhaps_write_key_update(&mut self, _sess: &mut ClientSessionImpl) {
    }
}

pub fn illegal_param(sess: &mut ClientSessionImpl, why: &str) -> TLSError {
    sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
    TLSError::PeerMisbehavedError(why.to_string())
}

pub fn check_aligned_handshake(sess: &mut ClientSessionImpl) -> Result<(), TLSError> {
    if !sess.common.handshake_joiner.is_empty() {
        sess.common.send_fatal_alert(AlertDescription::UnexpectedMessage);
        Err(TLSError::PeerMisbehavedError("key epoch or handshake flight with pending fragment".to_string()))
    } else {
        Ok(())
    }
}

fn find_session(sess: &mut ClientSessionImpl, dns_name: webpki::DNSNameRef)
                -> Option<persist::ClientSessionValue> {
    let key = persist::ClientSessionKey::session_for_dns_name(dns_name);
    let key_buf = key.get_encoding();

    let maybe_value = sess.config.session_persistence.get(&key_buf);

    if maybe_value.is_none() {
        debug!("No cached session for {:?}", dns_name);
        return None;
    }

    let value = maybe_value.unwrap();
    let mut reader = Reader::init(&value[..]);
    if let Some(result) = persist::ClientSessionValue::read(&mut reader) {
        if result.has_expired(ticketer::timebase()) {
            None
        } else {
            #[cfg(feature = "quic")] {
                if sess.common.is_quic() {
                    let params = PayloadU16::read(&mut reader)?;
                    sess.common.quic.params = Some(params.0);
                }
            }
            Some(result)
        }
    } else {
        None
    }
}

fn random_sessionid() -> SessionID {
    let mut random_id = [0u8; 32];
    rand::fill_random(&mut random_id);
    SessionID::new(&random_id)
}

/// If we have a ticket, we use the sessionid as a signal that we're
/// doing an abbreviated handshake.  See section 3.4 in RFC5077.
fn random_sessionid_for_ticket(csv: &mut persist::ClientSessionValue) {
    if !csv.ticket.0.is_empty() {
        csv.session_id = random_sessionid();
    }
}

struct InitialState {
    handshake: HandshakeDetails,
}

impl InitialState {
    fn new(host_name: webpki::DNSName, extra_exts: Vec<ClientExtension>) -> InitialState {
        InitialState {
            handshake: HandshakeDetails::new(host_name, extra_exts),
        }
    }

    fn emit_initial_client_hello(mut self, sess: &mut ClientSessionImpl) -> NextState {
        if sess.config.client_auth_cert_resolver.has_certs() {
            self.handshake.transcript.set_client_auth_enabled();
        }
        let hello_details = ClientHelloDetails::new();
        self.handshake.print_runtime("START");
        emit_client_hello_for_retry(sess, self.handshake, hello_details, None)
    }
}


pub fn start_handshake(sess: &mut ClientSessionImpl, host_name: webpki::DNSName,
                       extra_exts: Vec<ClientExtension>) -> NextState {
    InitialState::new(host_name, extra_exts)
        .emit_initial_client_hello(sess)
}

struct ExpectServerHello {
    handshake: HandshakeDetails,
    early_key_schedule: Option<KeyScheduleEarly>,
    handshake_secret: Option<KeyScheduleHandshake>,
    pdkext: Option<ClientExtension>,
    proactive_static_shared_secret: Option<oqs::kem::SharedSecret>,
    clean_transcript: Option<hash_hs::HandshakeHash>,
    hello: ClientHelloDetails,
    server_cert: ServerCertDetails,
    may_send_cert_status: bool,
    must_issue_new_ticket: bool,
    client_auth: Option<ClientAuthDetails>,
}

struct ExpectServerHelloOrHelloRetryRequest(ExpectServerHello);

pub fn compatible_suite(sess: &ClientSessionImpl,
                        resuming_suite: Option<&suites::SupportedCipherSuite>) -> bool {
    match resuming_suite {
        Some(resuming_suite) => {
            if let Some(suite) = sess.common.get_suite() {
                suite.can_resume_to(&resuming_suite)
            } else {
                true
            }
        }
        None => false
    }
}

fn emit_client_hello_for_retry(sess: &mut ClientSessionImpl,
                               mut handshake: HandshakeDetails,
                               mut hello: ClientHelloDetails,
                               retryreq: Option<&HelloRetryRequest>) -> NextState {
    // Do we have a SessionID or ticket cached for this host?
    handshake.resuming_session = find_session(sess, handshake.dns_name.as_ref());
    let (session_id, ticket, resume_version) = if handshake.resuming_session.is_some() {
        let resuming = handshake.resuming_session.as_mut().unwrap();
        if resuming.version == ProtocolVersion::TLSv1_2 {
            random_sessionid_for_ticket(resuming);
        }
        debug!("Resuming session");
        (resuming.session_id, resuming.ticket.0.clone(), resuming.version)
    } else {
        debug!("Not resuming any session");
        if handshake.session_id.is_empty() && !sess.common.is_quic() {
            handshake.session_id = random_sessionid();
        }
        (handshake.session_id, Vec::new(), ProtocolVersion::Unknown(0))
    };

    let support_tls12 = sess.config.supports_version(ProtocolVersion::TLSv1_2);
    let support_tls13 = sess.config.supports_version(ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::TLSv1_3);
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    let mut exts = Vec::new();
    if !supported_versions.is_empty() {
        exts.push(ClientExtension::SupportedVersions(supported_versions));
    }
    if sess.config.enable_sni {
        exts.push(ClientExtension::make_sni(handshake.dns_name.as_ref()));
    }
    exts.push(ClientExtension::ECPointFormats(ECPointFormatList::supported()));
    exts.push(ClientExtension::NamedGroups(suites::KeyExchange::supported_groups().to_vec()));
    exts.push(ClientExtension::SignatureAlgorithms(sess.config.get_verifier().supported_verify_schemes()));
    exts.push(ClientExtension::ExtendedMasterSecretRequest);
    exts.push(ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp()));

    let mut proactive_static_shared_secret = None;
    let mut semi_static_kemtls_key = None; // 1RTT-KEMTLS
    let mut pdkext = None; // 1RTT-KEMTLS (pop C_s from transcript)

    if !sess.config.known_certificates.is_empty() {
        if support_tls13 {
            if let Some((ext, ss)) = ClientExtension::make_proactive_ciphertext(&sess.config.known_certificates, handshake.dns_name.as_ref()) {
                exts.push(ext);
                proactive_static_shared_secret = Some(ss);
                handshake.print_runtime("CREATED PDK ENCAPSULATION")
            } else {
                // send the RFC7924 thing if we're not doing PDK
                exts.push(ClientExtension::make_cached_certs(&sess.config.known_certificates));
            }
        }

        // 1RTT-KEMTLS
        // the folowing two conditions are enough for the prototype; for real deployement one needs to make sure
        // that the client uses KEM algorithms i.e. leaf certificate signature is a KEM  
        if sess.config.client_auth_cert_resolver.has_certs() && sess.ssrtt_data.is_some(){
            if let Some((epoch, key)) = sess.ssrtt_data.clone() {
                // SSKC := SemiStaticKEMCiphertext t_{s,c} , C_{s, tsc} and K_s^{tsc} := sskemtls
                if let Some((sskc, sskemtls)) = ClientExtension::encapsulate_1rtt_pk(&key, epoch) {
                    pdkext = exts.pop();
                    exts.push(sskc);
                    semi_static_kemtls_key = Some(sskemtls);
                    handshake.print_runtime("CREATED PDK 1RTT-KEMTLS ENCAPSULATION")
                } else {
                    // send the RFC7924 thing if we're not doing PDK
                    exts.push(ClientExtension::make_cached_certs(&sess.config.known_certificates));
                }
            }
        }
    }
    

    if sess.config.ct_logs.is_some() {
        exts.push(ClientExtension::SignedCertificateTimestampRequest);
    }

    if support_tls13 {
        tls13::choose_kx_groups(sess, &mut exts, &mut hello, &mut handshake, retryreq);
    }

    if let Some(cookie) = retryreq.and_then(HelloRetryRequest::get_cookie) {
        exts.push(ClientExtension::Cookie(cookie.clone()));
    }

    if support_tls13 && sess.config.enable_tickets {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        let psk_modes = vec![ PSKKeyExchangeMode::PSK_DHE_KE ];
        exts.push(ClientExtension::PresharedKeyModes(psk_modes));
    }

    if !sess.config.alpn_protocols.is_empty() {
        exts.push(ClientExtension::Protocols(ProtocolNameList::from_slices(&sess.config
            .alpn_protocols
            .iter()
            .map(|proto| &proto[..])
            .collect::<Vec<_>>()
        )));
    }

    // Extra extensions must be placed before the PSK extension
    exts.extend(handshake.extra_exts.iter().cloned());

    let fill_in_binder = if support_tls13 && sess.config.enable_tickets &&
                            resume_version == ProtocolVersion::TLSv1_3 &&
                            !ticket.is_empty() {
        tls13::prepare_resumption(sess, ticket, &handshake, &mut exts,
                                  retryreq.is_some())
    } else if sess.config.enable_tickets {
        // If we have a ticket, include it.  Otherwise, request one.
        if ticket.is_empty() {
            exts.push(ClientExtension::SessionTicketRequest);
        } else {
            exts.push(ClientExtension::SessionTicketOffer(Payload::new(ticket)));
        }
        false
    } else {
        false
    };

    let is_pdk = proactive_static_shared_secret.is_some();

    // indicate KEMTLS-PDK client auth is coming
    if sess.config.client_auth_cert_resolver.has_certs() && is_pdk {
        exts.push(ClientExtension::ProactiveClientAuth);
    }

    // Note what extensions we sent.
    hello.sent_extensions = exts.iter()
        .map(ClientExtension::get_type)
        .collect();

    let mut chp = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from_slice(&handshake.randoms.client),
            session_id,
            cipher_suites: sess.get_cipher_suites(),
            compression_methods: vec![Compression::Null],
            extensions: exts,
        }),
    };

    // This will be used for 1RTT-KEMTLS
    let is_pdssk = semi_static_kemtls_key.is_some() ;
    let mut handshake_secret = None;

    let early_key_schedule = if fill_in_binder {
        Some(tls13::fill_in_psk_binder(sess, &mut handshake, &mut chp))
    } else if let Some(ss) = &proactive_static_shared_secret {
        if !is_pdssk {
             // ES <- HKDF.Extract(0, K_S)   
            Some(KeyScheduleEarly::new(ALL_CIPHERSUITES[0].hkdf_algorithm, ss.as_ref()))            
        }else {
            // 1RTT-KEMTLS
            let sskemtls = semi_static_kemtls_key.unwrap();
            // ES <- HKDF.Extract(0,Ks^{tsc})
            let early_secret = KeyScheduleEarly::new(ALL_CIPHERSUITES[0].hkdf_algorithm, sskemtls.as_ref());            
            // HS <- HKDF.Extract(ES,Ks)
            handshake_secret = Some(early_secret.clone().into_handshake(ss.as_ref()));
            handshake.print_runtime("DERIVED HS");
            // Return ES for 1RTT-KEMTLS when epochs do not match
            Some(early_secret)
        }
    } else {
        None
    };



    let ch = Message {
        typ: ContentType::Handshake,
        // "This value MUST be set to 0x0303 for all records generated
        //  by a TLS 1.3 implementation other than an initial ClientHello
        //  (i.e., one not generated after a HelloRetryRequest)"
        version: if retryreq.is_some() {
            ProtocolVersion::TLSv1_2
        } else {
            ProtocolVersion::TLSv1_0
        },
        payload: MessagePayload::Handshake(chp),
    };

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        tls13::emit_fake_ccs(&mut handshake, sess);
    }

    trace!("Sending ClientHello {:#?}", ch);
    handshake.print_runtime("SENDING CHELO");

    handshake.transcript.add_message(&ch);
    sess.common.send_msg(ch, false);

    let mut maybe_client_auth = None;
    let mut clean_transcript = None;
    // Calculate the hash of ClientHello and use it to derive EarlyTrafficSecret
    if sess.early_data.is_enabled() {
        // For middlebox compatibility
        tls13::emit_fake_ccs(&mut handshake, sess);
        // It is safe to call unwrap() because fill_in_binder is true.
        let resuming_suite = handshake.resuming_session
            .as_ref()
            .and_then(|resume| sess.find_cipher_suite(resume.cipher_suite)).unwrap();
        let client_hello_hash = handshake.transcript.get_hash_given(resuming_suite.get_hash(), &[]);
        let client_early_traffic_secret = early_key_schedule
            .as_ref()
            .unwrap()
            .client_early_traffic_secret(&client_hello_hash,
                                         &*sess.config.key_log,
                                         &handshake.randoms.client);
        // Set early data encryption key
        sess.common
            .record_layer
            .set_message_encrypter(cipher::new_tls13_write(resuming_suite, &client_early_traffic_secret));

        #[cfg(feature = "quic")]
        {
            sess.common.quic.early_secret = Some(client_early_traffic_secret);
        }

        // Now the client can send encrypted early data
        sess.common.early_traffic = true;
        trace!("Starting early data traffic");
    } else if sess.config.client_auth_cert_resolver.has_certs() && is_pdk {
        let issuers = sess.config.known_certificates.iter().map(|c| {
            let crt = webpki::EndEntityCert::from(&c.0).unwrap();            
            crt.subject().to_vec()
        }).collect::<Vec<_>>();
        use crate::msgs::enums::SignatureScheme;
        let refissuers = issuers.iter().map(|c| c.as_ref()).collect::<Vec<_>>();
        let maybe_certkey = sess.config.client_auth_cert_resolver.resolve(&refissuers,
                                            include!("../generated/pq_kemschemes.rs"));
        if let Some(mut certkey) = maybe_certkey {
            if certkey.key.algorithm() == SignatureAlgorithm::KEMTLS {
                tls13::emit_fake_ccs(&mut handshake, sess);
                // If 1RTT-KEMTLS is activated then use handshake_secret
                // else use early_key schedule
                let mut transcript_hash = handshake.transcript.get_hash_given(ALL_CIPHERSUITES[0].get_hash(), &[]); 
                if is_pdssk {
                    // 1RTT-KEMTLS
                    match handshake_secret {
                        None => panic!("problem in handshake secret"),
                        Some(ref mut hs) => {
                            // EHTS <- HKDF.Expand(ES, "e hs traffic"||H(CH))
                            let write_key = early_key_schedule.as_ref()
                                                                .unwrap()
                                                                .early_handshake_traffic_secret(
                                                                                            &transcript_hash,
                                                                                            &*sess.config.key_log,
                                                                                            &handshake.randoms.client);
                            sess.common
                                    .record_layer
                                    .set_message_encrypter(cipher::new_tls13_write(ALL_CIPHERSUITES[0],
                                                                &write_key));
                            // Now the client can send encrypted early data
                            sess.common.early_traffic = true;
                            trace!("Starting early data traffic");

                            // {CKC := ClientKEMCiphertext}_stage1 : Cs
                            let ciphertext = ClientExtension::from_extension_to_ciphertext(pdkext.clone().unwrap());
                            clean_transcript = Some(tls13::emit_client_kem_ciphertext(&mut handshake, sess, ciphertext));

                            // CHTS <- HKDF.Expand (HS, "c hs traffic", H(CH, . . . , CKC))
                            // we have to use this function since transcript.ctx is empty (client and server did not agree
                            // on a hash algorithm)
                            transcript_hash = handshake.transcript.get_hash_given(ALL_CIPHERSUITES[0].get_hash(),&[]);
                            let client_handshake_traffic_secret = hs.client_handshake_traffic_secret(&transcript_hash,
                                                                                        &*sess.config.key_log,
                                                                                        &handshake.randoms.client);
                            // prepare encryption with CHTS
                            sess.common
                                .record_layer
                                .set_message_encrypter(cipher::new_tls13_write(ALL_CIPHERSUITES[0],
                                                                        &client_handshake_traffic_secret));
                            debug!("Attempting semi-static 1RTT KEMTLS client stage 3");
                            // stage 2 should be used after receiving server hello
                            // SHTS <- HKDF.Expand (HS, "s hs traffic", H(CH, . . . , CKC))
                            let server_handshake_traffic_secret = hs.server_handshake_traffic_secret(&transcript_hash,
                                &*sess.config.key_log,
                                &handshake.randoms.client);
                            sess.common
                                .record_layer
                                .prepare_message_decrypter(cipher::new_tls13_read(ALL_CIPHERSUITES[0],&server_handshake_traffic_secret));
                            // stage 4 should be computed after emitting ClientCertificate
                        }
                    }
                }else {
                    // CETS <- HKDF.expand(ES,"c e traffic", CH..SH)
                    let client_early_traffic_secret = early_key_schedule
                                                    .as_ref()
                                                    .unwrap()
                                                    .client_early_traffic_secret(&transcript_hash,
                                                                                &*sess.config.key_log,
                                                                                &handshake.randoms.client);
                    // prepare encryption with CETS
                    // {CC:ClientCertificate}_CETS : cert[pk_c]
                    sess.common.record_layer
                        .set_message_encrypter(cipher::new_tls13_write(ALL_CIPHERSUITES[0], &client_early_traffic_secret));
                    debug!("Attempting pdk client auth");
                };
                let mut client_auth = ClientAuthDetails::new();
                client_auth.private_key = Some(certkey.key.get_bytes().to_vec());
                client_auth.cert = Some(certkey.take_cert());
                client_auth.auth_context = None;
                tls13::emit_certificate_tls13(&mut handshake, &mut client_auth, sess);
                maybe_client_auth = Some(client_auth);
                if is_pdssk { // 1RTT-KEMTLS
                    match handshake_secret {
                        None => panic!("problem in handshake secret"),
                        Some(ref mut hs) => {
                            // ETS <- HKDF.Expand (HS, "c e traffic", H(CH, . . . , CKC))
                            let early_traffic_secret = hs.early_traffic_secret(&transcript_hash,
                                                                            &*sess.config.key_log,
                                                                            &handshake.randoms.client);
                            // prepare encryption with CHTS
                            sess.common
                                .record_layer
                                .set_message_encrypter(cipher::new_tls13_write(ALL_CIPHERSUITES[0],
                                                                        &early_traffic_secret));
                            debug!("Attempting semi-static 1RTT KEMTLS client stage 4");
                        }
                    }
                }
            }
        }
    }

    let next = ExpectServerHello {
        handshake,
        hello,
        early_key_schedule,
        // 1RTT-KEMTLS
        handshake_secret,
        pdkext,
        proactive_static_shared_secret,
        clean_transcript,
        server_cert: ServerCertDetails::new(),
        may_send_cert_status: false,
        must_issue_new_ticket: false,
        client_auth: maybe_client_auth,
    };

    if support_tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest(next))
    } else {
        Box::new(next)
    }
}

pub fn process_alpn_protocol(sess: &mut ClientSessionImpl,
                             proto: Option<&[u8]>)
                             -> Result<(), TLSError> {
    sess.alpn_protocol = proto.map(ToOwned::to_owned);
    if sess.alpn_protocol.is_some() &&
        !sess.config.alpn_protocols.contains(sess.alpn_protocol.as_ref().unwrap()) {
        return Err(illegal_param(sess, "server sent non-offered ALPN protocol"));
    }
    debug!(
        "ALPN protocol is {:?}",
        sess.alpn_protocol
            .as_ref()
            .map(|v| bs_debug::BsDebug(&v))
    );
    Ok(())
}

pub fn sct_list_is_invalid(scts: &SCTList) -> bool {
    scts.is_empty() ||
        scts.iter().any(|sct| sct.0.is_empty())
}

impl ExpectServerHello {
    fn start_handshake_traffic(mut self,
                               sess: &mut ClientSessionImpl,
                               server_hello: &ServerHelloPayload,
                                ) ->  NextStateOrError {
        let suite = sess.common.get_suite_assert();
        let handshake_secret = self.handshake_secret.take();
        let their_key_share = server_hello.get_key_share()
            .ok_or_else(|| {
                sess.common.send_fatal_alert(AlertDescription::MissingExtension);
                TLSError::PeerMisbehavedError("missing key share".to_string())
                })?;
        
        let hello = &mut self.hello;
        let our_key_share = hello.find_key_share_and_discard_others(their_key_share.group)
            .ok_or_else(|| illegal_param(sess, "wrong group for key share"))?;
    
        // Ke <- KEM.Decap(ske,Ce)
        (&self.handshake).print_runtime("DECAPSULATING EPHEMERAL");
        let shared = our_key_share.decapsulate(&their_key_share.payload.0)
            .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed".to_string()))?;
        (&self.handshake).print_runtime("DECAPSULATED EPHEMERAL");

        if let Some(selected_psk) = server_hello.get_psk_index() {
            if let Some(ref resuming) = self.handshake.resuming_session {
                let resume_from_suite = sess.find_cipher_suite(resuming.cipher_suite).unwrap();
                if !resume_from_suite.can_resume_to(suite) {
                    return Err(illegal_param(sess, "server resuming incompatible suite"));
                }

                // If the server varies the suite here, we will have encrypted early data with
                // the wrong suite.
                if sess.early_data.is_enabled() && resume_from_suite != suite {
                    return Err(illegal_param(sess, "server varied suite with early data"));
                }

                if selected_psk != 0 {
                    return Err(illegal_param(sess, "server selected invalid psk"));
                }

                debug!("Resuming using PSK");
                // The key schedule has been initialized and set in fill_in_psk_binder()
            } else {
                return Err(TLSError::PeerMisbehavedError("server selected unoffered psk".to_string()));
            }
            // 1RTT-KEMTLS author: not sure what to send here in case of resumption;
            todo!("TODO: Resumption in case of tls 1.3 with preshared keys")
        }else if server_hello.find_extension(ExtensionType::ProactiveCiphertext).is_some() {
            let dns_name_ref =  self.handshake.dns_name.clone();
            let next_state = match server_hello.find_extension(ExtensionType::IsEqualEpoch){
                Some(_) => // 1RTT-KEMTLS with equal epochs
                    self.into_expect_ciphertext(handshake_secret.unwrap(), shared.clone(), true),
                None => { // Either 1RTT-KEMTLS with different epochs or PDK-KEMTLS
                    if handshake_secret.is_some(){
                        // We are in 1RTT-KEMTLS with different epochs
                        // Set the handshake.transcript as (CH, SSKC, SH)
                        self.handshake.transcript.copy_transcript(self.clean_transcript.take().unwrap());
                        // ES <- HKDF.Extract(0,Ke)
                        let early_secret = KeyScheduleEarly::new(suite.hkdf_algorithm, shared.as_ref());            
                        // EHTS <- HKDF.Expand(ES, "e hs traffic"||H(CH SSKC SH))
                        let write_key = early_secret.early_handshake_traffic_secret(
                                                            &self.handshake.transcript.get_current_hash(),
                                                            &*sess.config.key_log,
                                                            &self.handshake.randoms.client);
                        sess.common.record_layer
                                    .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
                        // {CKC := ClientKEMCiphertext}_stage 1 : Cs
                        let ciphertext = ClientExtension::from_extension_to_ciphertext(self.pdkext.take().unwrap());
                        tls13::emit_client_kem_ciphertext(&mut self.handshake, sess, ciphertext);
                        // HS <- HKDF.Extract(ES,Ks)
                        let mut handshake_secret = early_secret.into_handshake(self.proactive_static_shared_secret.take().unwrap().as_ref());
                        self.handshake.print_runtime("DERIVED HS");

                        let hs_hash = self.handshake.transcript.get_current_hash();
                        // SHTS <- HKDF.Expand (HS, "s hs traffic" || H(CH, SSKC, SH, CKC))
                        let server_handshake_traffic_secret = handshake_secret.server_handshake_traffic_secret(
                                                                                                    &hs_hash,
                                                                                                    &*sess.config.key_log,
                                                                                                    &self.handshake.randoms.client);
                        sess.common
                            .record_layer
                            .set_message_decrypter(cipher::new_tls13_read(suite,&server_handshake_traffic_secret));

                        // CHTS <- HKDF.Expand (HS, "c hs traffic" || H(CH, SSKC, SH, CKC))
                        let client_handshake_traffic_secret = handshake_secret.client_handshake_traffic_secret(&hs_hash,
                                                                                                    &*sess.config.key_log,
                                                                                                    &self.handshake.randoms.client);
                        // prepare encryption with CHTS
                        sess.common
                            .record_layer
                            .set_message_encrypter(cipher::new_tls13_write(suite,
                                                                        &client_handshake_traffic_secret));
                        // {CC := ClientCertificate}_stage 3 : cert[pk c ]
                        if let Some(ref mut client_auth) = self.client_auth{
                            tls13::emit_certificate_tls13(&mut self.handshake, client_auth, sess);
                        }
                        // ETS <- HKDF.Expand (HS, "c e traffic"kH(CH, SSKC, SH, CKC))
                        let early_traffic_secret = handshake_secret.early_traffic_secret(&hs_hash,
                                                                            &*sess.config.key_log,
                                                                            &self.handshake.randoms.client);
                        sess.common
                            .record_layer
                            .set_message_encrypter(cipher::new_tls13_write(suite,
                                                                        &early_traffic_secret));
                        self.into_expect_ciphertext(handshake_secret, shared.clone(), false)
                    }else{
                        // We are in PDK-KEMTLS
                        debug!("Using PDK");
                        let early_key_schedule = self.early_key_schedule.take();
                        // ES <- HKDF.Extract(dES, ss)
                        let mut key_schedule = early_key_schedule.unwrap().into_handshake(&shared);

                        // XXX: transmit CCS as late as possible. This seems to fix weird TCP side effects
                        // with large certificates (Dilithium).
                        // tls13::emit_fake_ccs(&mut self.handshake, sess);
                        let write_key = key_schedule.client_handshake_traffic_secret(
                                    &self.handshake.transcript.get_current_hash(),
                                    &*sess.config.key_log,
                                    &self.handshake.randoms.client);
                        sess.common.record_layer
                            .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
                        // SHTS <- HKDF.Expand(HS, "s hs traffic", CH..SH)
                        let read_key = key_schedule.server_handshake_traffic_secret(
                                                        &self.handshake.transcript.get_current_hash(),
                                                        &*sess.config.key_log,
                                                        &self.handshake.randoms.client);
                        sess.common.record_layer
                            .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
                        
                        self.into_expect_tls13_encrypted_extensions(key_schedule, true)
                    }
                },
            };
             // Remember what KX group the server liked for next time.
            tls13::save_kx_hint(sess, dns_name_ref.as_ref(), their_key_share.group);
            // If we change keying when a subsequent handshake message is being joined,
            // the two halves will have different record layer protections.  Disallow this.
            check_aligned_handshake(sess)?;
            return Ok(next_state);
        } else {
            debug!("Not resuming");
            // Discard the early data key schedule.
            sess.early_data.rejected();
            sess.common.early_traffic = false;
            self.handshake.resuming_session.take();
            // Remember what KX group the server liked for next time.
            tls13::save_kx_hint(sess, self.handshake.dns_name.as_ref(), their_key_share.group);
            // If we change keying when a subsequent handshake message is being joined,
            // the two halves will have different record layer protections.  Disallow this.
            check_aligned_handshake(sess)?;

            let mut key_schedule = KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(&shared);
            self.handshake.hash_at_client_recvd_server_hello = self.handshake.transcript.get_current_hash();
            if !sess.early_data.is_enabled() {
                // CHTS <- HKDF.Expand(HS, "c hs traffic", H(CH..SH))
                let write_key = key_schedule.client_handshake_traffic_secret(
                                    &self.handshake.hash_at_client_recvd_server_hello,
                                    &*sess.config.key_log,
                                    &self.handshake.randoms.client);
                sess.common.record_layer
                    .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
                // SHTS <- HKDF.Expand(HS, "s hs traffic", CH..SH)
                let read_key = key_schedule.server_handshake_traffic_secret(
                                                &self.handshake.hash_at_client_recvd_server_hello,
                                                &*sess.config.key_log,
                                                &self.handshake.randoms.client);
                sess.common.record_layer
                    .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
                #[cfg(feature = "quic")] {
                    sess.common.quic.hs_secrets = Some(quic::Secrets {
                        client: write_key,
                        server: read_key,
                    });
                }
            } else {
                #[cfg(feature = "quic")] {
                    // Traffic secret wasn't computed and stored above, so do it here.
                    let write_key = key_schedule
                            .client_handshake_traffic_secret(&self.handshake.hash_at_client_recvd_server_hello,
                                                            &*sess.config.key_log,
                                                            &self.handshake.randoms.client);
                    let read_key = key_schedule
                            .server_handshake_traffic_secret(&self.handshake.hash_at_client_recvd_server_hello,
                                                            &*sess.config.key_log,
                                                            &self.handshake.randoms.client);
                    sess.common.quic.hs_secrets = Some(quic::Secrets {
                        client: write_key,
                        server: read_key,
                    });
                }
            }
            return Ok(self.into_expect_tls13_encrypted_extensions(key_schedule, false))
        }
    }

    // 1RTT-KEMTLS
    fn into_expect_ciphertext(self, key_schedule: KeyScheduleHandshake, ephemeral_key: Vec<u8>, is_eq_epoch: bool) -> NextState {
        Box::new(tls13::ExpectCiphertext {
            handshake: self.handshake,
            server_cert: Some(self.server_cert),
            hello: Some(self.hello),
            key_schedule,
            client_auth: self.client_auth.unwrap(),
            is_pdk: false,
            is_eq_epoch_sskemtls: Some(is_eq_epoch),
            ephemeral_key: Some(ephemeral_key),
        })
    }

    fn into_expect_tls13_encrypted_extensions(self, key_schedule: KeyScheduleHandshake, is_pdk: bool) -> NextState {
        Box::new(tls13::ExpectEncryptedExtensions {
            handshake: self.handshake,
            key_schedule,
            server_cert: self.server_cert,
            hello: self.hello,
            is_pdk,
            is_sskemtls: false,
            client_auth: self.client_auth,
            spk: None,
        })
    }

    fn into_expect_tls12_new_ticket_resume(self,
                                           secrets: SessionSecrets,
                                           certv: verify::ServerCertVerified,
                                           sigv: verify::HandshakeSignatureValid) -> NextState {
        Box::new(tls12::ExpectNewTicket {
            secrets,
            handshake: self.handshake,
            resuming: true,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }

    fn into_expect_tls12_ccs_resume(self,
                                    secrets: SessionSecrets,
                                    certv: verify::ServerCertVerified,
                                    sigv: verify::HandshakeSignatureValid) -> NextState {
        Box::new(tls12::ExpectCCS {
            secrets,
            handshake: self.handshake,
            ticket: ReceivedTicketDetails::new(),
            resuming: true,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }

    fn into_expect_tls12_certificate(self) -> NextState {
        Box::new(tls12::ExpectCertificate {
            handshake: self.handshake,
            server_cert: self.server_cert,
            may_send_cert_status: self.may_send_cert_status,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl State for ExpectServerHello {
    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let server_hello = require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {:#?}", server_hello);
        self.handshake.print_runtime("RECEIVED SH");


        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let tls13_supported = sess.config.supports_version(TLSv1_3);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello.get_supported_versions()
              .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        match server_version {
            TLSv1_3 if tls13_supported => {
                sess.common.negotiated_version = Some(TLSv1_3);
            }
            TLSv1_2 if sess.config.supports_version(TLSv1_2) => {
                if sess.early_data.is_enabled() && sess.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(TLSError::PeerMisbehavedError("server chose v1.2 when offering 0-rtt"
                        .to_string()));
                }
                sess.common.negotiated_version = Some(TLSv1_2);

                if server_hello.get_supported_versions().is_some() {
                    return Err(illegal_param(sess, "server chose v1.2 using v1.3 extension"));
                }
            }
            _ => {
                sess.common.send_fatal_alert(AlertDescription::ProtocolVersion);
                return Err(TLSError::PeerIncompatibleError("server does not support TLS v1.2/v1.3"
                    .to_string()));
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err(illegal_param(sess, "server chose non-Null compression"));
        }

        if server_hello.has_duplicate_extension() {
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
            return Err(TLSError::PeerMisbehavedError("server sent duplicate extensions".to_string()));
        }

        let allowed_unsolicited = [ ExtensionType::RenegotiationInfo ];
        if self.hello.server_sent_unsolicited_extensions(&server_hello.extensions,
                                                         &allowed_unsolicited) {
            sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TLSError::PeerMisbehavedError("server sent unsolicited extension".to_string()));
        }

        // Extract ALPN protocol
        if !sess.common.is_tls13() {
            process_alpn_protocol(sess, server_hello.get_alpn_protocol())?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = server_hello.get_ecpoints_extension() {
            if !point_fmts.contains(&ECPointFormat::Uncompressed) {
                sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
                return Err(TLSError::PeerMisbehavedError("server does not support uncompressed points"
                                                         .to_string()));
            }
        }

        let scs = sess.find_cipher_suite(server_hello.cipher_suite);

        if scs.is_none() {
            sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
            return Err(TLSError::PeerMisbehavedError("server chose non-offered ciphersuite"
                .to_string()));
        }

        debug!("Using ciphersuite {:?}", server_hello.cipher_suite);
        if !sess.common.set_suite(scs.unwrap()) {
            return Err(illegal_param(sess, "server varied selected ciphersuite"));
        }

        let version = sess.common.negotiated_version.unwrap();
        if !sess.common.get_suite_assert().usable_for_version(version) {
            return Err(illegal_param(sess, "server chose unusable ciphersuite for version"));
        }

        // prepare SHTS for 1RTT-KEMTLS before adding the HS to transcript
        if self.handshake_secret.is_some() {
            // prepare decryption with SHTS
            sess.common.record_layer.start_decrypting();
            debug!("Attempting semi-static 1RTT KEMTLS client stage 2"); 
        }
        // Start our handshake hash, and input the server-hello.
        let starting_hash = sess.common.get_suite_assert().get_hash();
        self.handshake.transcript.start_hash(starting_hash);
        self.handshake.transcript.add_message(&m);
        // if we are in 1RTT-KEMTLS then we have to add SH to the clean transcript
        // later on, if the epochs do not match, then handshake.transcript will be 
        // replaced by clean_transcript which contains (CH, SSKC, SH)
        if let Some(ref mut clean_transcript) = self.clean_transcript{
            clean_transcript.add_message(&m);
        };


        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        if sess.common.is_tls13() {
            tls13::validate_server_hello(sess, &server_hello)?;  
            // This is the main function
            let next_state = self.start_handshake_traffic(sess,&server_hello)?;
            return Ok(next_state)
        }

        // TLS1.2 only from here-on
        // Save ServerRandom and SessionID
        server_hello.random.write_slice(&mut self.handshake.randoms.server);
        self.handshake.session_id = server_hello.session_id;

        // Look for TLS1.3 downgrade signal in server random
        if tls13_supported && self.handshake.randoms.has_tls12_downgrade_marker() {
            return Err(illegal_param(sess, "downgrade to TLS1.2 when TLS1.3 is supported"));
        }

        // Doing EMS?
        if server_hello.ems_support_acked() {
            self.handshake.using_ems = true;
        }

        // Might the server send a ticket?
        let with_tickets = if server_hello.find_extension(ExtensionType::SessionTicket).is_some() {
            debug!("Server supports tickets");
            true
        } else {
            false
        };
        self.must_issue_new_ticket = with_tickets;

        // Might the server send a CertificateStatus between Certificate and
        // ServerKeyExchange?
        if server_hello.find_extension(ExtensionType::StatusRequest).is_some() {
            debug!("Server may staple OCSP response");
            self.may_send_cert_status = true;
        }

        // Save any sent SCTs for verification against the certificate.
        if let Some(sct_list) = server_hello.get_sct_list() {
            debug!("Server sent {:?} SCTs", sct_list.len());

            if sct_list_is_invalid(sct_list) {
                let error_msg = "server sent invalid SCT list".to_string();
                return Err(TLSError::PeerMisbehavedError(error_msg));
            }
            self.server_cert.scts = Some(sct_list.clone());
        }

        // See if we're successfully resuming.
        if let Some(ref resuming) = self.handshake.resuming_session {
            if resuming.session_id == self.handshake.session_id {
                debug!("Server agreed to resume");

                // Is the server telling lies about the ciphersuite?
                if resuming.cipher_suite != scs.unwrap().suite {
                    let error_msg = "abbreviated handshake offered, but with varied cs".to_string();
                    return Err(TLSError::PeerMisbehavedError(error_msg));
                }

                // And about EMS support?
                if resuming.extended_ms != self.handshake.using_ems {
                    let error_msg = "server varied ems support over resume".to_string();
                    return Err(TLSError::PeerMisbehavedError(error_msg));
                }

                let secrets = SessionSecrets::new_resume(&self.handshake.randoms,
                                                         scs.unwrap().get_hash(),
                                                         &resuming.master_secret.0);
                sess.config.key_log.log("CLIENT_RANDOM",
                                        &secrets.randoms.client,
                                        &secrets.master_secret);
                sess.common.start_encryption_tls12(&secrets);

                // Since we're resuming, we verified the certificate and
                // proof of possession in the prior session.
                sess.server_cert_chain = resuming.server_cert_chain.clone();
                let certv = verify::ServerCertVerified::assertion();
                let sigv =  verify::HandshakeSignatureValid::assertion();

                return if self.must_issue_new_ticket {
                    Ok(self.into_expect_tls12_new_ticket_resume(secrets, certv, sigv))
                } else {
                    Ok(self.into_expect_tls12_ccs_resume(secrets, certv, sigv))
                };
            }
        }

        Ok(self.into_expect_tls12_certificate())
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState {
        Box::new(self.0)
    }

    fn handle_hello_retry_request(mut self, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let hrr = require_handshake_msg!(m, HandshakeType::HelloRetryRequest, HandshakePayload::HelloRetryRequest)?;
        trace!("Got HRR {:?}", hrr);
        warn!("HRR!");

        check_aligned_handshake(sess)?;

        let has_cookie = hrr.get_cookie().is_some();
        let req_group = hrr.get_requested_key_share_group();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        if !has_cookie && req_group.map(|g| self.0.hello.has_key_share(g)).unwrap_or(false) {
            return Err(illegal_param(sess, "server requested hrr with our group"));
        }

        // Or asks for us to retry on an unsupported group.
        if let Some(group) = req_group {
            if !suites::KeyExchange::supported_groups().contains(&group) {
                return Err(illegal_param(sess, "server requested hrr with bad group"));
            }
        }

        // Or has an empty cookie.
        if has_cookie && hrr.get_cookie().unwrap().0.is_empty() {
            return Err(illegal_param(sess, "server requested hrr with empty cookie"));
        }

        // Or has something unrecognised
        if hrr.has_unknown_extension() {
            sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TLSError::PeerIncompatibleError("server sent hrr with unhandled extension"
                                                       .to_string()));
        }

        // Or has the same extensions more than once
        if hrr.has_duplicate_extension() {
            return Err(illegal_param(sess, "server send duplicate hrr extensions"));
        }

        // Or asks us to change nothing.
        if !has_cookie && req_group.is_none() {
            return Err(illegal_param(sess, "server requested hrr with no changes"));
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.get_supported_versions() {
            Some(ProtocolVersion::TLSv1_3) => {
                sess.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err(illegal_param(sess, "server requested unsupported version in hrr"));
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        let maybe_cs = sess.find_cipher_suite(hrr.cipher_suite);
        let cs = match maybe_cs {
            Some(cs) => cs,
            None => {
                return Err(illegal_param(sess, "server requested unsupported cs in hrr"));
            }
        };

        // HRR selects the ciphersuite.
        sess.common.set_suite(cs);

        // This is the draft19 change where the transcript became a tree
        self.0.handshake.transcript.start_hash(cs.get_hash());
        self.0.handshake.transcript.rollup_for_hrr();
        self.0.handshake.transcript.add_message(&m);

        // Early data is not alllowed after HelloRetryrequest
        if sess.early_data.is_enabled() {
            sess.early_data.rejected();
        }

        Ok(emit_client_hello_for_retry(sess,
                                       self.0.handshake,
                                       self.0.hello,
                                       Some(&hrr)))
    }
}

impl State for ExpectServerHelloOrHelloRetryRequest {
    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        check_message(&m,
                      &[ContentType::Handshake],
                      &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest])?;
        if m.is_handshake_type(HandshakeType::ServerHello) {
            self.into_expect_server_hello().handle(sess, m)
        } else {
            self.handle_hello_retry_request(sess, m)
        }
    }
}

pub fn send_cert_error_alert(sess: &mut ClientSessionImpl, err: TLSError) -> TLSError {
    match err {
        TLSError::WebPKIError(webpki::Error::BadDER) => {
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
        }
        TLSError::PeerMisbehavedError(_) => {
            sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
        }
        _ => {
            sess.common.send_fatal_alert(AlertDescription::BadCertificate);
        }
    };

    err
}
