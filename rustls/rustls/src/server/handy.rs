use crate::Epoch;
use crate::sign;
use crate::key;
use webpki;
use crate::server;
use crate::error::TLSError;
use crate::server::ClientHello;

use std::collections;
use std::sync::{Arc, Mutex};

/// Something which never stores sessions.
pub struct NoServerSessionStorage {}

impl server::StoresServerSessions for NoServerSessionStorage {
    fn put(&self, _id: Vec<u8>, _sec: Vec<u8>) -> bool {
        false
    }
    fn get(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn take(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// An implementor of `StoresServerSessions` that stores everything
/// in memory.  If enforces a limit on the number of stored sessions
/// to bound memory usage.
pub struct ServerSessionMemoryCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    max_entries: usize,
}

impl ServerSessionMemoryCache {
    /// Make a new ServerSessionMemoryCache.  `size` is the maximum
    /// number of stored sessions.
    pub fn new(size: usize) -> Arc<ServerSessionMemoryCache> {
        debug_assert!(size > 0);
        Arc::new(ServerSessionMemoryCache {
            cache: Mutex::new(collections::HashMap::new()),
            max_entries: size,
        })
    }

    fn limit_size(&self) {
        let mut cache = self.cache.lock().unwrap();
        while cache.len() > self.max_entries {
            let k = cache.keys().next().unwrap().clone();
            cache.remove(&k);
        }
    }
}

impl server::StoresServerSessions for ServerSessionMemoryCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.lock()
            .unwrap()
            .insert(key, value);
        self.limit_size();
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock()
            .unwrap()
            .get(key).cloned()
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock()
            .unwrap()
            .remove(key)
    }
}

/// Something which never produces tickets.
pub struct NeverProducesTickets {}

impl server::ProducesTickets for NeverProducesTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn get_lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Something which never resolves a certificate.
pub struct FailResolveChain {}

impl server::ResolvesServerCert for FailResolveChain {
    fn resolve(&self, _client_hello: ClientHello) -> Option<sign::CertifiedKey> {
        None
    }
}

/// Something which always resolves to the same cert chain.
pub struct AlwaysResolvesChain(sign::CertifiedKey);

impl AlwaysResolvesChain {
    /// Creates an `AlwaysResolvesChain`, auto-detecting the underlying private
    /// key type and encoding.
    pub fn new(chain: Vec<key::Certificate>,
               priv_key: &key::PrivateKey) -> Result<AlwaysResolvesChain, TLSError> {
        let key = sign::any_supported_type(priv_key)
            .map_err(|_| TLSError::General("invalid private key".into()))?;
        Ok(AlwaysResolvesChain(sign::CertifiedKey::new(chain, Arc::new(key))))
    }

    /// Creates an `AlwaysResolvesChain`, auto-detecting the underlying private
    /// key type and encoding.
    ///
    /// If non-empty, the given OCSP response and SCTs are attached.
    pub fn new_with_extras(chain: Vec<key::Certificate>,
                           priv_key: &key::PrivateKey,
                           ocsp: Vec<u8>,
                           scts: Vec<u8>) -> Result<AlwaysResolvesChain, TLSError> {
        let mut r = AlwaysResolvesChain::new(chain, priv_key)?;
        if !ocsp.is_empty() {
            r.0.ocsp = Some(ocsp);
        }
        if !scts.is_empty() {
            r.0.sct_list = Some(scts);
        }
        Ok(r)
    }
}

impl server::ResolvesServerCert for AlwaysResolvesChain {
    fn resolve(&self, _client_hello: ClientHello) -> Option<sign::CertifiedKey> {
        Some(self.0.clone())
    }
}

/// Something that resolves do different cert chains/keys based
/// on client-supplied server name (via SNI).
pub struct ResolvesServerCertUsingSNI {
    by_name: collections::HashMap<String, sign::CertifiedKey>,
}

impl ResolvesServerCertUsingSNI {
    /// Create a new and empty (ie, knows no certificates) resolver.
    pub fn new() -> ResolvesServerCertUsingSNI {
        ResolvesServerCertUsingSNI { by_name: collections::HashMap::new() }
    }

    /// Add a new `sign::CertifiedKey` to be used for the given SNI `name`.
    ///
    /// This function fails if `name` is not a valid DNS name, or if
    /// it's not valid for the supplied certificate, or if the certificate
    /// chain is syntactically faulty.
    pub fn add(&mut self, name: &str, ck: sign::CertifiedKey) -> Result<(), TLSError> {
        let checked_name = webpki::DNSNameRef::try_from_ascii_str(name)
            .map_err(|_| TLSError::General("Bad DNS name".into()))?;

        ck.cross_check_end_entity_cert(Some(checked_name))?;
        self.by_name.insert(name.into(), ck);
        Ok(())
    }
}

impl server::ResolvesServerCert for ResolvesServerCertUsingSNI {
    fn resolve(&self, client_hello: ClientHello) -> Option<sign::CertifiedKey> {
        if let Some(name) = client_hello.server_name() {
            self.by_name.get(name.into())
                .cloned()
        } else {
            // This kind of resolver requires SNI
            None
        }
    }
}

/// Very simple resolver for 1rtt server keys.
/// Could do much fancier stuff with vecs etc.
/// Does not assume Epoch values are orderable
pub struct AlwaysResolves1RTTServerKeys {
    current: (Epoch, Vec<u8>, key::PrivateKey),
    next: Option<(Epoch, Vec<u8>, key::PrivateKey)>,
}

impl AlwaysResolves1RTTServerKeys {
    /// Create a new resolver
    pub fn new(epoch: Epoch, pk: Vec<u8>, sk: key::PrivateKey) -> Self {
        AlwaysResolves1RTTServerKeys {
            current: (epoch, pk, sk),
            next: None,
        }
    }

    /// Set the next epoch
    pub fn set_next(&mut self, epoch: Epoch, pk: Vec<u8>, sk: key::PrivateKey) {
        self.next = Some((epoch, pk, sk));
    }
}

impl server::Resolves1RTTServerKeys for AlwaysResolves1RTTServerKeys {
    fn get(&self, epoch: &Epoch) -> Option<key::PrivateKey> {
        if epoch == &self.current.0 {
            Some(self.current.2.clone())
        } else if let Some((nextep, _, nextsk)) = &self.next {
            if nextep == epoch {
                Some(nextsk.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    fn next(&self, current: Option<&Epoch>) -> Option<(Epoch, Vec<u8>)> {
        if current.is_none() {
            return Some((self.current.0.clone(), self.current.1.clone()));
        }
        let current = current.unwrap();
        if let Some((nextep, nextpk, _)) = &self.next {
            if nextep == current {
                None
            } else {
                Some((nextep.clone(), nextpk.clone()))
            }
        } else if current != &self.current.0 {
            Some((self.current.0.clone(), self.current.1.clone()))
        } else {
            None
        }
    }
}

/// Resolver that simply always returns None, for when PDK-SS isn't set up
pub struct NeverResolves1RTTServerKeys;

impl server::Resolves1RTTServerKeys for NeverResolves1RTTServerKeys {
    fn get(&self, _epoch: &Epoch) -> Option<key::PrivateKey> {
        None
    }

    fn next(&self, _current: Option<&Epoch>) -> Option<(Epoch, Vec<u8>)> {
        None
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::StoresServerSessions;
    use crate::server::ProducesTickets;
    use crate::server::ResolvesServerCert;

    #[test]
    fn test_noserversessionstorage_drops_put() {
        let c = NoServerSessionStorage {};
        assert_eq!(c.put(vec![0x01], vec![0x02]), false);
    }

    #[test]
    fn test_noserversessionstorage_denies_gets() {
        let c = NoServerSessionStorage {};
        c.put(vec![0x01], vec![0x02]);
        assert_eq!(c.get(&[]), None);
        assert_eq!(c.get(&[0x01]), None);
        assert_eq!(c.get(&[0x02]), None);
    }

    #[test]
    fn test_noserversessionstorage_denies_takes() {
        let c = NoServerSessionStorage {};
        assert_eq!(c.take(&[]), None);
        assert_eq!(c.take(&[0x01]), None);
        assert_eq!(c.take(&[0x02]), None);
    }

    #[test]
    fn test_serversessionmemorycache_accepts_put() {
        let c = ServerSessionMemoryCache::new(4);
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
    }

    #[test]
    fn test_serversessionmemorycache_persists_put() {
        let c = ServerSessionMemoryCache::new(4);
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
    }

    #[test]
    fn test_serversessionmemorycache_overwrites_put() {
        let c = ServerSessionMemoryCache::new(4);
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
        assert_eq!(c.put(vec![0x01], vec![0x04]), true);
        assert_eq!(c.get(&[0x01]), Some(vec![0x04]));
    }

    #[test]
    fn test_serversessionmemorycache_drops_to_maintain_size_invariant() {
        let c = ServerSessionMemoryCache::new(4);
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
        assert_eq!(c.put(vec![0x03], vec![0x04]), true);
        assert_eq!(c.put(vec![0x05], vec![0x06]), true);
        assert_eq!(c.put(vec![0x07], vec![0x08]), true);
        assert_eq!(c.put(vec![0x09], vec![0x0a]), true);

        let mut count = 0;
        if c.get(&[0x01]).is_some() { count += 1; }
        if c.get(&[0x03]).is_some() { count += 1; }
        if c.get(&[0x05]).is_some() { count += 1; }
        if c.get(&[0x07]).is_some() { count += 1; }
        if c.get(&[0x09]).is_some() { count += 1; }

        assert_eq!(count, 4);
    }

    #[test]
    fn test_neverproducestickets_does_nothing() {
        let npt = NeverProducesTickets {};
        assert_eq!(false, npt.enabled());
        assert_eq!(0, npt.get_lifetime());
        assert_eq!(None, npt.encrypt(&[]));
        assert_eq!(None, npt.decrypt(&[]));
    }

    #[test]
    fn test_failresolvechain_does_nothing() {
        let frc = FailResolveChain {};
        assert!(frc.resolve(ClientHello::new(None, &[], None)).is_none());
    }

    #[test]
    fn test_resolvesservercertusingsni_requires_sni() {
        let rscsni = ResolvesServerCertUsingSNI::new();
        assert!(rscsni.resolve(ClientHello::new(None, &[], None)).is_none());
    }

    #[test]
    fn test_resolvesservercertusingsni_handles_unknown_name() {
        let rscsni = ResolvesServerCertUsingSNI::new();
        let name = webpki::DNSNameRef::try_from_ascii_str("hello.com").unwrap();
        assert!(rscsni.resolve(ClientHello::new(Some(name), &[], None)).is_none());
    }
}
