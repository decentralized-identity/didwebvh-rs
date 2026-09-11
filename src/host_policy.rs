//! Which hosts network resolution may contact.
//!
//! A `did:webvh` DID names the host its log is fetched from, so whoever
//! supplies the DID chooses where the resolver sends HTTP requests. The
//! [`HostPolicy`] carried in `ResolveOptions::host_policy` (with the `network`
//! feature) limits that choice. The default, [`HostPolicy::PublicOnly`], is
//! enforced in three layers:
//!
//! 1. **Address literals.** A DID whose host is an IP address is always
//!    rejected, whatever the policy: did:webvh requires a domain name
//!    (`WebVHURL::parse_did_url`).
//! 2. **Names.** Special-use and non-public names (`localhost`,
//!    `*.localhost`, `*.local`, `*.internal`, `home.arpa`, and single-label
//!    names) are rejected before any network I/O.
//! 3. **Resolved addresses** (native targets). The HTTP client this crate
//!    builds resolves names through `guarded_dns_resolver`, which fails
//!    closed when *any* address returned for a name is non-public, and hands
//!    the connector only the vetted addresses. There is no second lookup
//!    between the check and the connection.
//!
//! Layer 3 lives in the HTTP client. A caller who supplies their own client
//! through `ResolveOptions::http_client` owns it: build that client with
//! `guarded_dns_resolver` (or an equivalent) to keep it. In a browser
//! (`wasm32-unknown-unknown`) DNS is not observable, so only layers 1 and 2
//! apply there.

use crate::DIDWebVHError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Which hosts network resolution may contact.
///
/// IP-address hosts are rejected by did:webvh parsing under every policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HostPolicy {
    /// Contact public hosts only. The default.
    ///
    /// Refused before any request is made: `localhost`, `*.localhost`,
    /// `*.local`, `*.internal`, `home.arpa` / `*.home.arpa`, and single-label
    /// names.
    ///
    /// Refused at connect time by the native HTTP client this crate builds: a
    /// name for which any resolved address is loopback, unspecified,
    /// RFC 1918, carrier-grade NAT (100.64.0.0/10), link-local (169.254.0.0/16,
    /// fe80::/10), unique-local (fc00::/7), site-local, multicast, reserved,
    /// benchmarking or documentation space, or an IPv4-mapped,
    /// IPv4-compatible, NAT64 or 6to4 address embedding one of those. IPv6
    /// outside global unicast (2000::/3) is refused as a whole.
    ///
    /// Every fetch uses `https://`.
    #[default]
    PublicOnly,

    /// Contact any host, including loopback and private-network hosts.
    ///
    /// For local development and tests (`did:webvh:{SCID}:localhost%3A8000`),
    /// and for deployments whose did:webvh hosts are trusted and live on a
    /// private network. Choose it only where the DIDs being resolved are
    /// trusted.
    ///
    /// `localhost` and `*.localhost` are fetched over plain `http://`; every
    /// other host uses `https://`.
    AllowPrivate,
}

impl HostPolicy {
    /// Check a domain name, as it appears in a DID or URL, against this
    /// policy.
    ///
    /// This is the name half of the check. Whether the name *resolves* to a
    /// non-public address is decided at connect time by the HTTP client (see
    /// the [module documentation](self)).
    pub fn check_host(self, host: &str) -> Result<(), DIDWebVHError> {
        match self {
            Self::AllowPrivate => Ok(()),
            Self::PublicOnly => {
                if host_is_blocked(host) {
                    Err(DIDWebVHError::BlockedHost(format!(
                        "{host} is not a public host (HostPolicy::PublicOnly)"
                    )))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// URL scheme used to fetch from `host` under this policy.
    pub(crate) fn fetch_scheme(self, host: &str) -> &'static str {
        if self == Self::AllowPrivate && is_loopback_name(host) {
            "http"
        } else {
            "https"
        }
    }
}

/// Lower-case, strip IPv6 brackets and any trailing root dots. A trailing dot
/// is legal in a hostname and survives URL normalisation, so `localhost.` must
/// compare equal to `localhost`.
fn normalise(host: &str) -> String {
    let h = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// `true` when `name` equals `suffix` or ends with `.{suffix}`. Exact label
/// matching: `localhost.example.com` is not under `localhost`.
fn is_name_or_subdomain(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// RFC 6761 loopback names: `localhost` and `*.localhost`.
pub(crate) fn is_loopback_name(host: &str) -> bool {
    is_name_or_subdomain(&normalise(host), "localhost")
}

/// Names that are non-public by definition. Expects a normalised name.
fn name_is_blocked(name: &str) -> bool {
    // Single-label names are resolved through search domains or local
    // configuration (`metadata`, `kubernetes`), never through public DNS.
    if name.is_empty() || !name.contains('.') {
        return true;
    }
    ["localhost", "local", "internal", "home.arpa"]
        .iter()
        .any(|suffix| is_name_or_subdomain(name, suffix))
}

/// Classify a host as written in a URL: an IP literal by address, anything
/// else by name.
pub(crate) fn host_is_blocked(host: &str) -> bool {
    let h = normalise(host);
    match h.parse::<IpAddr>() {
        Ok(ip) => ip_is_blocked(ip),
        Err(_) => name_is_blocked(&h),
    }
}

/// `true` for any address that is not publicly routable.
pub(crate) fn ip_is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => ipv4_is_blocked(a),
        IpAddr::V6(a) => ipv6_is_blocked(a),
    }
}

fn ipv4_is_blocked(a: Ipv4Addr) -> bool {
    let [o0, o1, o2, _] = a.octets();
    o0 == 0 // 0.0.0.0/8 "this network", includes 0.0.0.0
        || o0 == 10 // 10.0.0.0/8
        || (o0 == 100 && (o1 & 0xc0) == 64) // 100.64.0.0/10 carrier-grade NAT (incl. 100.100.100.200)
        || o0 == 127 // 127.0.0.0/8 loopback
        || (o0 == 169 && o1 == 254) // 169.254.0.0/16 link-local (incl. 169.254.169.254)
        || (o0 == 172 && (o1 & 0xf0) == 16) // 172.16.0.0/12
        || (o0 == 192 && o1 == 0 && o2 == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o0 == 192 && o1 == 0 && o2 == 2) // 192.0.2.0/24 TEST-NET-1
        || (o0 == 192 && o1 == 168) // 192.168.0.0/16
        || (o0 == 198 && (o1 & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || (o0 == 198 && o1 == 51 && o2 == 100) // 198.51.100.0/24 TEST-NET-2
        || (o0 == 203 && o1 == 0 && o2 == 113) // 203.0.113.0/24 TEST-NET-3
        || o0 >= 224 // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, broadcast
}

fn ipv6_is_blocked(a: Ipv6Addr) -> bool {
    if a.is_unspecified() || a.is_loopback() {
        return true;
    }
    // IPv4-mapped (::ffff:a.b.c.d) and the deprecated IPv4-compatible
    // (::a.b.c.d) forms reach the embedded IPv4 destination on stacks that
    // route them. `to_ipv4` covers both.
    if let Some(v4) = a.to_ipv4() {
        return ipv4_is_blocked(v4);
    }
    let s = a.segments();
    let embedded = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    // IPv4-translated ::ffff:0:a.b.c.d (SIIT).
    if s[..4] == [0, 0, 0, 0] && s[4] == 0xffff && s[5] == 0 {
        return ipv4_is_blocked(embedded(s[6], s[7]));
    }
    // NAT64 well-known prefix 64:ff9b::/96 embeds its IPv4 destination.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return ipv4_is_blocked(embedded(s[6], s[7]));
    }
    // Everything outside global unicast 2000::/3 is non-public: this covers
    // ::/8, 100::/64 discard, 64:ff9b:1::/48 local-use NAT64, fc00::/7
    // unique-local (incl. fd00:ec2::254), fe80::/10 link-local, fec0::/10
    // site-local and ff00::/8 multicast.
    if (s[0] & 0xe000) != 0x2000 {
        return true;
    }
    // 6to4 2002::/16 embeds an IPv4 address in bits 16..48.
    if s[0] == 0x2002 {
        return ipv4_is_blocked(embedded(s[1], s[2]));
    }
    // 2001::/23 IETF protocol assignments (incl. Teredo 2001::/32) and
    // 2001:db8::/32 documentation.
    (s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
        // 3fff::/20 documentation.
        || (s[0] == 0x3fff && s[1] < 0x1000)
}

/// The error placed in reqwest's error source chain when the guarded
/// resolver refuses a name. The resolved address is deliberately not part of
/// the message; it is logged at `debug` level instead.
#[cfg(feature = "network")]
#[derive(Debug)]
pub(crate) struct BlockedResolution {
    host: String,
}

#[cfg(feature = "network")]
impl std::fmt::Display for BlockedResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} resolves to a non-public address (HostPolicy::PublicOnly)",
            self.host
        )
    }
}

#[cfg(feature = "network")]
impl std::error::Error for BlockedResolution {}

/// Find a [`BlockedResolution`] anywhere in an error's source chain.
#[cfg(feature = "network")]
pub(crate) fn blocked_resolution_in_chain<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a BlockedResolution> {
    let mut next = Some(err);
    while let Some(e) = next {
        if let Some(blocked) = e.downcast_ref::<BlockedResolution>() {
            return Some(blocked);
        }
        next = e.source();
    }
    None
}

#[cfg(all(
    feature = "network",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
pub use native::{guarded_dns_resolver, guarded_dns_resolver_with};

#[cfg(all(
    feature = "network",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
mod native {
    use super::{BlockedResolution, host_is_blocked, ip_is_blocked};
    use reqwest::dns::{Addrs, Name, Resolve, Resolving};
    use std::{net::SocketAddr, sync::Arc};

    type BoxError = Box<dyn std::error::Error + Send + Sync>;

    /// A [`reqwest::dns::Resolve`] that enforces [`HostPolicy::PublicOnly`]
    /// at connect time, using the system resolver for lookups.
    ///
    /// It refuses special-use names outright, fails closed on the whole name
    /// when any resolved address is non-public, and returns only vetted
    /// addresses, which are the ones reqwest connects to. This is the resolver
    /// the default resolution client uses. Install it on a client passed as
    /// `ResolveOptions::http_client` to keep the same protection:
    ///
    /// ```no_run
    /// use didwebvh_rs::{host_policy::guarded_dns_resolver, resolve::ResolveOptions};
    ///
    /// let client = reqwest::Client::builder()
    ///     .dns_resolver(guarded_dns_resolver())
    ///     .redirect(reqwest::redirect::Policy::none())
    ///     .no_proxy()
    ///     .build()?;
    /// let options = ResolveOptions::default().with_http_client(client);
    /// # Ok::<(), reqwest::Error>(())
    /// ```
    ///
    /// A proxy resolves the target name itself, so this resolver never sees
    /// it: keep `no_proxy()` on a client that relies on it.
    ///
    /// [`HostPolicy::PublicOnly`]: super::HostPolicy::PublicOnly
    pub fn guarded_dns_resolver() -> Arc<dyn Resolve> {
        Arc::new(GuardedResolver { inner: None })
    }

    /// Like [`guarded_dns_resolver`], but performs lookups through `inner`
    /// (for example a caller's own DNS resolver) and vets its answers.
    pub fn guarded_dns_resolver_with(inner: Arc<dyn Resolve>) -> Arc<dyn Resolve> {
        Arc::new(GuardedResolver { inner: Some(inner) })
    }

    struct GuardedResolver {
        inner: Option<Arc<dyn Resolve>>,
    }

    impl Resolve for GuardedResolver {
        fn resolve(&self, name: Name) -> Resolving {
            Box::pin(vet(self.inner.clone(), name))
        }
    }

    async fn vet(inner: Option<Arc<dyn Resolve>>, name: Name) -> Result<Addrs, BoxError> {
        let host = name.as_str().to_owned();
        if host_is_blocked(&host) {
            return Err(Box::new(BlockedResolution { host }));
        }

        let addrs: Vec<SocketAddr> = match inner {
            Some(inner) => inner.resolve(name).await?.collect(),
            // Port 0: reqwest substitutes the URL's port.
            None => tokio::net::lookup_host((host.as_str(), 0)).await?.collect(),
        };

        if addrs.is_empty() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{host}: no addresses found"),
            )));
        }

        // Fail closed on the whole name: one non-public answer is enough.
        if let Some(bad) = addrs.iter().find(|a| ip_is_blocked(a.ip())) {
            tracing::debug!(
                host = host.as_str(),
                address = %bad.ip(),
                "refusing a name that resolves to a non-public address"
            );
            return Err(Box::new(BlockedResolution { host }));
        }

        Ok(Box::new(addrs.into_iter()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::WebVHURL;

    /// §6.2 `ip` vectors.
    #[test]
    fn ip_vectors_block() {
        for ip in [
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "169.254.169.254",
            "169.254.170.2",
            "100.64.0.1",
            "100.100.100.200",
            "100.127.255.254",
            "192.0.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::a00:1",
            "2002:7f00:1::1",
            "2001:0:4136:e378::1",
            "fc00::1",
            "fd00::1",
            "fd00:ec2::254",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "100::1",
            // Beyond the shared vectors.
            "::ffff:0:7f00:1",
            "3fff::1",
        ] {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(ip_is_blocked(addr), "{ip} should be blocked");
            assert!(host_is_blocked(ip), "{ip} should be blocked as a host");
        }
    }

    #[test]
    fn ip_vectors_allow() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "11.0.0.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.1",
            "169.253.255.255",
            "192.169.0.1",
            "198.20.0.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "64:ff9b::808:808",
            // Beyond the shared vectors.
            "2002:808:808::1",
            "[2606:4700:4700::1111]",
        ] {
            assert!(!host_is_blocked(ip), "{ip} should be allowed");
        }
    }

    /// §6.2 `url` vectors: parse and canonicalise with the WHATWG parser the
    /// resolver uses, then classify the host. A parse failure also counts as
    /// refused.
    #[test]
    fn url_vectors_block() {
        for u in [
            "https://2130706433/",
            "https://0x7f000001/",
            "https://017700000001/",
            "https://0177.0.0.1/",
            "https://0x7f.0.0.1/",
            "https://127.1/",
            "https://127.0.1/",
            "https://0/",
            "https://169.254.169.254./",
            "https://%31%32%37.0.0.1/",
            "https://①②⑦.0.0.1/",
            "https://127。0。0。1/",
            "https://[::ffff:127.0.0.1]/",
            "https://[0:0:0:0:0:ffff:7f00:1]/",
            "https://[::1]:8443/",
            "wss://0x7f.1/",
            "https://example.com@127.0.0.1/",
            "https://127.0.0.1\\@example.com/",
            // Invalid.
            "https://0x100000000/",
            "https://1.2.3.4.5/",
            "https://[fe80::1%25en0]/",
        ] {
            // A parse error means the URL is rejected as invalid.
            if let Ok(parsed) = url::Url::parse(u) {
                let host = parsed.host_str().unwrap_or_default();
                assert!(host_is_blocked(host), "{u} (host {host}) should be blocked");
            }
        }
    }

    /// §6.2 `names` vectors.
    #[test]
    fn name_vectors() {
        for u in [
            "https://localhost/",
            "https://LOCALHOST./",
            "https://svc.localhost/",
            "https://printer.local/",
            "https://kube-dns.kube-system.svc.cluster.local/",
            "https://metadata.google.internal/",
            "https://router.home.arpa/",
            "https://metadata/",
        ] {
            let parsed = url::Url::parse(u).unwrap();
            let host = parsed.host_str().unwrap();
            assert!(host_is_blocked(host), "{u} should be blocked");
            assert!(HostPolicy::PublicOnly.check_host(host).is_err());
            assert!(HostPolicy::AllowPrivate.check_host(host).is_ok());
        }
        for u in [
            "https://example.com/",
            "https://example.com./",
            "https://localhost.example.com/",
        ] {
            let parsed = url::Url::parse(u).unwrap();
            let host = parsed.host_str().unwrap();
            assert!(!host_is_blocked(host), "{u} should be allowed");
            assert!(HostPolicy::PublicOnly.check_host(host).is_ok());
        }
    }

    #[test]
    fn loopback_names_and_scheme() {
        for h in ["localhost", "LOCALHOST", "localhost.", "svc.localhost"] {
            assert!(is_loopback_name(h), "{h}");
            assert_eq!(HostPolicy::AllowPrivate.fetch_scheme(h), "http");
            assert_eq!(HostPolicy::PublicOnly.fetch_scheme(h), "https");
        }
        for h in ["localhost.example.com", "notlocalhost", "example.com"] {
            assert!(!is_loopback_name(h), "{h}");
            assert_eq!(HostPolicy::AllowPrivate.fetch_scheme(h), "https");
        }
    }

    /// §6.2 `webvh` vectors: DID to fetch URL.
    #[test]
    fn webvh_vectors() -> Result<(), DIDWebVHError> {
        let fetch = |did: &str, policy| {
            WebVHURL::parse_did_url(did)?
                .get_fetch_url("did.jsonl", policy)
                .map(|u| u.to_string())
        };
        assert_eq!(
            fetch("did:webvh:QmS:example.com", HostPolicy::PublicOnly)?,
            "https://example.com/.well-known/did.jsonl"
        );
        assert_eq!(
            fetch(
                "did:webvh:QmS:example.com:users:alice",
                HostPolicy::PublicOnly
            )?,
            "https://example.com/users/alice/did.jsonl"
        );
        // `localhost` as a path segment never changes the scheme.
        for policy in [HostPolicy::PublicOnly, HostPolicy::AllowPrivate] {
            assert_eq!(
                fetch("did:webvh:QmS:example.com:localhost", policy)?,
                "https://example.com/localhost/did.jsonl"
            );
        }

        for did in [
            "did:webvh:QmS:localhost%3A8000",
            "did:webvh:QmS:LOCALHOST%3A8000",
            "did:webvh:QmS:localhost.%3A8000",
            "did:webvh:QmS:local%68ost%3A8000",
            "did:webvh:QmS:ｌｏｃａｌｈｏｓｔ%3A8000",
            "did:webvh:QmS:svc.localhost",
            "did:webvh:QmS:printer.local",
            "did:webvh:QmS:metadata.google.internal",
            "did:webvh:QmS:router.home.arpa",
            "did:webvh:QmS:metadata",
        ] {
            let err = fetch(did, HostPolicy::PublicOnly).expect_err(did);
            assert!(matches!(err, DIDWebVHError::BlockedHost(_)), "{did}: {err}");
        }

        assert_eq!(
            fetch("did:webvh:QmS:localhost%3A8000", HostPolicy::AllowPrivate)?,
            "http://localhost:8000/.well-known/did.jsonl"
        );
        assert_eq!(
            fetch("did:webvh:QmS:LOCALHOST%3A8000", HostPolicy::AllowPrivate)?,
            "http://localhost:8000/.well-known/did.jsonl"
        );
        assert_eq!(
            fetch("did:webvh:QmS:printer.local", HostPolicy::AllowPrivate)?,
            "https://printer.local/.well-known/did.jsonl"
        );

        // IP literals are refused at parse time under every policy.
        for did in [
            "did:webvh:QmS:127.0.0.1",
            "did:webvh:QmS:2130706433",
            "did:webvh:QmS:169.254.169.254%3A80",
            "did:web:127.0.0.1%3A9099",
            "did:web:localhost",
        ] {
            assert!(WebVHURL::parse_did_url(did).is_err(), "{did}");
        }
        Ok(())
    }

    #[cfg(all(
        feature = "network",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    mod dns {
        use super::super::*;
        use crate::test_utils::StubResolver;
        use std::{str::FromStr, sync::atomic::Ordering};

        async fn lookup(
            answers: &[&str],
            name: &str,
        ) -> (
            Result<Vec<std::net::SocketAddr>, Box<dyn std::error::Error + Send + Sync>>,
            usize,
        ) {
            let stub = StubResolver::new(answers);
            let lookups = stub.lookups.clone();
            let resolver = guarded_dns_resolver_with(std::sync::Arc::new(stub));
            let result = resolver
                .resolve(reqwest::dns::Name::from_str(name).unwrap())
                .await
                .map(|addrs| addrs.collect());
            (result, lookups.load(Ordering::SeqCst))
        }

        fn is_blocked(err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
            err.downcast_ref::<BlockedResolution>().is_some()
        }

        /// §6.2 `dns` vectors, through a stub inner resolver.
        #[tokio::test]
        async fn dns_vectors() {
            let (ok, _) = lookup(&["93.184.216.34"], "a.test").await;
            assert_eq!(ok.unwrap().len(), 1);

            for (answers, name) in [
                (&["127.0.0.1"][..], "b.test"),
                (&["93.184.216.34", "10.0.0.1"][..], "c.test"),
                (&["::ffff:169.254.169.254"][..], "d.test"),
                (&["64:ff9b::7f00:1"][..], "e.test"),
            ] {
                let (result, lookups) = lookup(answers, name).await;
                let err = result.expect_err(name);
                assert!(is_blocked(err.as_ref()), "{name}: {err}");
                assert_eq!(lookups, 1, "{name}");
            }

            let (empty, _) = lookup(&[], "f.test").await;
            let err = empty.expect_err("empty answer must be an error");
            assert!(!is_blocked(err.as_ref()));
        }

        /// Blocked names are refused without a lookup.
        #[tokio::test]
        async fn blocked_names_skip_lookup() {
            for name in ["localhost", "svc.localhost", "printer.local", "metadata"] {
                let (result, lookups) = lookup(&["93.184.216.34"], name).await;
                assert!(is_blocked(result.expect_err(name).as_ref()), "{name}");
                assert_eq!(lookups, 0, "{name}");
            }
        }

        /// The system-resolver variant refuses `localhost`, which resolves to
        /// loopback on every host. No network is involved.
        #[tokio::test]
        async fn system_resolver_refuses_localhost() {
            let err = guarded_dns_resolver()
                .resolve(reqwest::dns::Name::from_str("localhost").unwrap())
                .await
                .err()
                .expect("localhost must be refused");
            assert!(is_blocked(err.as_ref()), "{err}");
        }

        /// The refusal survives reqwest's error wrapping.
        #[tokio::test]
        async fn refusal_is_recoverable_from_reqwest_error() {
            let client = reqwest::Client::builder()
                .dns_resolver(guarded_dns_resolver_with(std::sync::Arc::new(
                    StubResolver::new(&["127.0.0.1"]),
                )))
                .no_proxy()
                .build()
                .unwrap();
            let err = client
                .get("https://b.test:1/")
                .send()
                .await
                .expect_err("must be refused");
            assert!(blocked_resolution_in_chain(&err).is_some(), "{err:?}");
        }
    }
}
