//! Benchmarks for the work webpki performs on the TLS handshake hot path.
//!
//! These benchmarks are run continuously by CodSpeed. They deliberately re-use the
//! real-world certificates, chains and CRLs that live in `tests/`, so that the measured
//! work is representative of what a TLS client or server actually does:
//!
//! * parsing DER-encoded end-entity certificates and trust anchors,
//! * building and verifying a certification path (including signature verification),
//! * checking that a certificate is valid for a DNS name or IP address,
//! * parsing certificate revocation lists and searching them for a serial number.

use core::time::Duration;

use divan::Bencher;
use pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls_aws_lc_rs::ALL_VERIFICATION_ALGS;
use webpki::{
    BorrowedCertRevocationList, CertRevocationList, EndEntityCert, ExtendedKeyUsage,
    OwnedCertRevocationList, PathBuilder, RevocationCheckDepth, RevocationOptions,
    RevocationOptionsBuilder, UnknownStatusPolicy, anchor_from_trusted_cert,
};

fn main() {
    divan::main();
}

/// Parsing DER-encoded certificates.
mod parse {
    use super::*;

    /// Parse an end-entity certificate, the first thing done with a peer's certificate.
    #[divan::bench(args = ["cloudflare_dns", "netflix", "sanofi", "amazon_rsa2048"])]
    fn end_entity_cert(bencher: Bencher<'_, '_>, name: &str) {
        let der = CertificateDer::from(match name {
            "cloudflare_dns" => &include_bytes!("../tests/cloudflare_dns/ee.der")[..],
            "netflix" => &include_bytes!("../tests/netflix/ee.der")[..],
            "sanofi" => &include_bytes!("../tests/sanofi/ee.der")[..],
            "amazon_rsa2048" => {
                &include_bytes!("../tests/amazon/valid.rootca1.demo.amazontrust.com.cer")[..]
            }
            other => unreachable!("unknown end-entity certificate {other}"),
        });

        bencher.bench(|| EndEntityCert::try_from(divan::black_box(&der)).unwrap());
    }

    /// Extract a trust anchor from a trusted root certificate; done once per root in a
    /// trust store.
    #[divan::bench(args = ["rsa2048", "rsa4096", "ecdsa_p256", "ecdsa_p384"])]
    fn trust_anchor(bencher: Bencher<'_, '_>, name: &str) {
        let der = CertificateDer::from(match name {
            "rsa2048" => &include_bytes!("../tests/amazon/AmazonRootCA1.cer")[..],
            "rsa4096" => &include_bytes!("../tests/amazon/AmazonRootCA2.cer")[..],
            "ecdsa_p256" => &include_bytes!("../tests/amazon/AmazonRootCA3.cer")[..],
            "ecdsa_p384" => &include_bytes!("../tests/amazon/AmazonRootCA4.cer")[..],
            other => unreachable!("unknown root certificate {other}"),
        });

        bencher.bench(|| anchor_from_trusted_cert(divan::black_box(&der)).unwrap());
    }
}

/// Path building and verification, including certificate signature verification.
mod path {
    use super::*;

    /// Verify a three certificate RSA chain rooted at a Verisign v1 root.
    #[divan::bench]
    fn netflix(bencher: Bencher<'_, '_>) {
        bench_simple_chain(
            bencher,
            include_bytes!("../tests/netflix/ee.der"),
            Some(include_bytes!("../tests/netflix/inter.der")),
            include_bytes!("../tests/netflix/ca.der"),
            1_492_441_716, // 2017-04-17T15:08:36Z
        );
    }

    /// Verify a three certificate ECDSA chain.
    #[divan::bench]
    fn cloudflare_dns(bencher: Bencher<'_, '_>) {
        bench_simple_chain(
            bencher,
            include_bytes!("../tests/cloudflare_dns/ee.der"),
            Some(include_bytes!("../tests/cloudflare_dns/inter.der")),
            include_bytes!("../tests/cloudflare_dns/ca.der"),
            1_663_495_771, // 2022-09-18T08:49:31Z
        );
    }

    /// Verify a three certificate RSA chain where the signature algorithm parameters are absent.
    #[divan::bench]
    fn sanofi(bencher: Bencher<'_, '_>) {
        bench_simple_chain(
            bencher,
            include_bytes!("../tests/sanofi/ee.der"),
            Some(include_bytes!("../tests/sanofi/inter.der")),
            include_bytes!("../tests/sanofi/ca.der"),
            1_746_549_566, // 2025-05-06T17:39:26Z
        );
    }

    /// Verify a two certificate Ed25519 chain.
    #[divan::bench]
    fn ed25519(bencher: Bencher<'_, '_>) {
        bench_simple_chain(
            bencher,
            include_bytes!("../tests/ed25519/ee.der"),
            None,
            include_bytes!("../tests/ed25519/ca.der"),
            1_547_363_522, // 2019-01-13T07:12:02Z
        );
    }

    /// Verify an end-entity certificate against a single trust anchor, with at most one
    /// intermediate certificate offered by the peer.
    fn bench_simple_chain(
        bencher: Bencher<'_, '_>,
        ee: &'static [u8],
        intermediate: Option<&'static [u8]>,
        ca: &'static [u8],
        now: u64,
    ) {
        let ca = CertificateDer::from(ca);
        let anchors = [anchor_from_trusted_cert(&ca).unwrap()];
        let intermediates = intermediate
            .map(CertificateDer::from)
            .into_iter()
            .collect::<Vec<_>>();

        let ee = CertificateDer::from(ee);
        let cert = EndEntityCert::try_from(&ee).unwrap();
        let time = UnixTime::since_unix_epoch(Duration::from_secs(now));

        bencher.bench(|| {
            PathBuilder::new(
                &intermediates,
                None,
                &ExtendedKeyUsage::SERVER_AUTH,
                ALL_VERIFICATION_ALGS,
                &anchors,
            )
            .build(divan::black_box(&cert), time)
            .unwrap()
        });
    }

    /// The Amazon Trust demo end-entity certificates, one per root key type.
    const AMAZON_END_ENTITIES: [&str; 4] = ["rsa2048", "rsa4096", "ecdsa_p256", "ecdsa_p384"];

    /// Verify a demo certificate against the full set of Amazon Trust roots and intermediates.
    ///
    /// This exercises path building with a realistic amount of candidate issuers: 4 trust
    /// anchors and 16 intermediate certificates.
    #[divan::bench(args = AMAZON_END_ENTITIES)]
    fn amazon(bencher: Bencher<'_, '_>, name: &str) {
        let store = AmazonStore::new();
        let ee = CertificateDer::from(amazon_end_entity(name));
        let cert = EndEntityCert::try_from(&ee).unwrap();

        bencher.bench(|| {
            PathBuilder::new(
                &store.intermediates,
                None,
                &ExtendedKeyUsage::SERVER_AUTH,
                ALL_VERIFICATION_ALGS,
                &store.anchors,
            )
            .build(divan::black_box(&cert), AmazonStore::TIME)
            .unwrap()
        });
    }

    /// Verify a demo certificate as above, while also checking the end-entity certificate
    /// against the CRLs published for the Amazon Trust intermediates.
    #[divan::bench(args = AMAZON_END_ENTITIES)]
    fn amazon_with_revocation(bencher: Bencher<'_, '_>, name: &str) {
        let store = AmazonStore::new();
        let crls = crl::amazon_intermediate_crls();
        let crls = crls.iter().collect::<Vec<_>>();
        let ee = CertificateDer::from(amazon_end_entity(name));
        let cert = EndEntityCert::try_from(&ee).unwrap();

        bencher.bench(|| {
            PathBuilder::new(
                &store.intermediates,
                Some(revocation_options(&crls)),
                &ExtendedKeyUsage::SERVER_AUTH,
                ALL_VERIFICATION_ALGS,
                &store.anchors,
            )
            .build(divan::black_box(&cert), AmazonStore::TIME)
            .unwrap()
        });
    }

    fn revocation_options<'a>(crls: &'a [&'a CertRevocationList<'a>]) -> RevocationOptions<'a> {
        RevocationOptionsBuilder::new(crls)
            .unwrap()
            .with_depth(RevocationCheckDepth::EndEntity)
            .with_status_policy(UnknownStatusPolicy::Allow)
            .build()
    }

    fn amazon_end_entity(name: &str) -> &'static [u8] {
        match name {
            "rsa2048" => {
                &include_bytes!("../tests/amazon/valid.rootca1.demo.amazontrust.com.cer")[..]
            }
            "rsa4096" => {
                &include_bytes!("../tests/amazon/valid.rootca2.demo.amazontrust.com.cer")[..]
            }
            "ecdsa_p256" => {
                &include_bytes!("../tests/amazon/valid.rootca3.demo.amazontrust.com.cer")[..]
            }
            "ecdsa_p384" => {
                &include_bytes!("../tests/amazon/valid.rootca4.demo.amazontrust.com.cer")[..]
            }
            other => unreachable!("unknown Amazon end-entity certificate {other}"),
        }
    }

    /// The Amazon Trust roots and intermediates, as a client would have them available.
    struct AmazonStore {
        anchors: Vec<TrustAnchor<'static>>,
        intermediates: Vec<CertificateDer<'static>>,
    }

    impl AmazonStore {
        /// Sun Feb 23 02:02:16 PST 2025, a time at which the demo certificates are valid.
        const TIME: UnixTime = UnixTime::since_unix_epoch(Duration::from_secs(1_740_304_936));

        fn new() -> Self {
            const ROOTS: &[&[u8]] = &[
                include_bytes!("../tests/amazon/AmazonRootCA1.cer"),
                include_bytes!("../tests/amazon/AmazonRootCA2.cer"),
                include_bytes!("../tests/amazon/AmazonRootCA3.cer"),
                include_bytes!("../tests/amazon/AmazonRootCA4.cer"),
            ];

            const INTERMEDIATES: &[&[u8]] = &[
                include_bytes!("../tests/amazon/r2m01.cer"),
                include_bytes!("../tests/amazon/r2m02.cer"),
                include_bytes!("../tests/amazon/r2m03.cer"),
                include_bytes!("../tests/amazon/r2m04.cer"),
                include_bytes!("../tests/amazon/r4m01.cer"),
                include_bytes!("../tests/amazon/r4m02.cer"),
                include_bytes!("../tests/amazon/r4m03.cer"),
                include_bytes!("../tests/amazon/r4m04.cer"),
                include_bytes!("../tests/amazon/e2m01.cer"),
                include_bytes!("../tests/amazon/e2m02.cer"),
                include_bytes!("../tests/amazon/e2m03.cer"),
                include_bytes!("../tests/amazon/e2m04.cer"),
                include_bytes!("../tests/amazon/e3m01.cer"),
                include_bytes!("../tests/amazon/e3m02.cer"),
                include_bytes!("../tests/amazon/e3m03.cer"),
                include_bytes!("../tests/amazon/e3m04.cer"),
            ];

            // The trust anchors borrow from the root certificate DER, which is `'static`.
            Self {
                anchors: ROOTS
                    .iter()
                    .copied()
                    .map(CertificateDer::from)
                    .map(|der| anchor_from_trusted_cert(&der).unwrap().to_owned())
                    .collect(),
                intermediates: INTERMEDIATES
                    .iter()
                    .copied()
                    .map(CertificateDer::from)
                    .collect(),
            }
        }
    }
}

/// Checking that a certificate is valid for a subject name.
mod name {
    use super::*;

    /// The subject names checked by [`subject_name`], keyed by benchmark argument.
    const SUBJECT_NAMES: [&str; 6] = [
        "dns_first_san",
        "dns_last_san",
        "dns_wildcard_san",
        "dns_mismatch",
        "ipv4",
        "ipv6",
    ];

    /// Verify a certificate against a DNS name or IP address.
    ///
    /// The DNS benchmarks use certificates with twelve subject alternative names, so that
    /// both the best case (an early match) and the worst case (a miss, requiring every name
    /// to be considered) are covered.
    #[divan::bench(args = SUBJECT_NAMES)]
    fn subject_name(bencher: Bencher<'_, '_>, name: &str) {
        let (cert_der, subject_name, expect_valid) = match name {
            "dns_first_san" => (
                &include_bytes!("../tests/netflix/ee.der")[..],
                ServerName::try_from("account.netflix.com").unwrap(),
                true,
            ),
            "dns_last_san" => (
                &include_bytes!("../tests/netflix/ee.der")[..],
                ServerName::try_from("www.netflix.com").unwrap(),
                true,
            ),
            "dns_wildcard_san" => (
                &include_bytes!("../tests/misc/dns_names_and_wildcards.der")[..],
                ServerName::try_from("unmatched.netflix.com").unwrap(),
                true,
            ),
            "dns_mismatch" => (
                &include_bytes!("../tests/netflix/ee.der")[..],
                ServerName::try_from("not-netflix.example.com").unwrap(),
                false,
            ),
            "ipv4" => (
                &include_bytes!("../tests/cloudflare_dns/ee.der")[..],
                ServerName::try_from("1.1.1.1".as_bytes()).unwrap(),
                true,
            ),
            "ipv6" => (
                &include_bytes!("../tests/cloudflare_dns/ee.der")[..],
                ServerName::try_from("2606:4700:4700:0000:0000:0000:0000:1111".as_bytes()).unwrap(),
                true,
            ),
            other => unreachable!("unknown subject name case {other}"),
        };

        let der = CertificateDer::from(cert_der);
        let cert = EndEntityCert::try_from(&der).unwrap();
        assert_eq!(
            cert.verify_is_valid_for_subject_name(&subject_name).is_ok(),
            expect_valid
        );

        bencher.bench(|| {
            cert.verify_is_valid_for_subject_name(divan::black_box(&subject_name))
                .is_ok()
        });
    }
}

/// Parsing and searching certificate revocation lists.
mod crl {
    use super::*;

    /// The CRLs used by the benchmarks in this module, keyed by benchmark argument.
    ///
    /// `amazon_root` is a small (~650 byte) CRL, `amazon_intermediate` is a large
    /// (~480 kilobyte) CRL with many thousands of revoked certificates.
    const CRLS: [&str; 2] = ["amazon_root", "amazon_intermediate"];

    /// A serial number that does not appear in any of the benchmark CRLs, so that searching
    /// for it has to consider every revoked certificate.
    const ABSENT_SERIAL: &[u8] = &[0xC0, 0xFF, 0xEE];

    fn crl_der(name: &str) -> &'static [u8] {
        match name {
            "amazon_root" => &include_bytes!("../tests/amazon/rootca1.crl")[..],
            "amazon_intermediate" => &include_bytes!("../tests/amazon/r2m02.crl")[..],
            other => unreachable!("unknown CRL {other}"),
        }
    }

    /// Parse a CRL into the borrowed, zero-copy representation.
    #[divan::bench(args = CRLS)]
    fn parse_borrowed(bencher: Bencher<'_, '_>, name: &str) {
        let der = crl_der(name);
        bencher.bench(|| BorrowedCertRevocationList::from_der(divan::black_box(der)).unwrap());
    }

    /// Parse a CRL into the owned representation, which indexes revoked serials up front.
    #[divan::bench(args = CRLS)]
    fn parse_owned(bencher: Bencher<'_, '_>, name: &str) {
        let der = crl_der(name);
        bencher.bench(|| OwnedCertRevocationList::from_der(divan::black_box(der)).unwrap());
    }

    /// Search the borrowed representation for a serial that does not appear, which requires
    /// a linear scan over the revoked certificates.
    #[divan::bench(args = CRLS)]
    fn find_serial_borrowed(bencher: Bencher<'_, '_>, name: &str) {
        let der = crl_der(name);
        let crl = CertRevocationList::from(BorrowedCertRevocationList::from_der(der).unwrap());

        bencher.bench(|| {
            crl.find_serial(divan::black_box(ABSENT_SERIAL))
                .unwrap()
                .is_some()
        });
    }

    /// Search the owned representation for a serial that does not appear, which is a lookup
    /// in the index built at parse time.
    #[divan::bench(args = CRLS)]
    fn find_serial_owned(bencher: Bencher<'_, '_>, name: &str) {
        let der = crl_der(name);
        let crl = CertRevocationList::from(OwnedCertRevocationList::from_der(der).unwrap());

        bencher.bench(|| {
            crl.find_serial(divan::black_box(ABSENT_SERIAL))
                .unwrap()
                .is_some()
        });
    }

    /// The CRLs published for the Amazon Trust intermediates, used by the path building
    /// benchmarks that enable revocation checking.
    pub(super) fn amazon_intermediate_crls() -> Vec<CertRevocationList<'static>> {
        const CRL_DER: &[&[u8]] = &[
            include_bytes!("../tests/amazon/r2m01.crl"),
            include_bytes!("../tests/amazon/r2m02.crl"),
            include_bytes!("../tests/amazon/r2m03.crl"),
            include_bytes!("../tests/amazon/r2m04.crl"),
            include_bytes!("../tests/amazon/r4m01.crl"),
            include_bytes!("../tests/amazon/r4m02.crl"),
            include_bytes!("../tests/amazon/r4m03.crl"),
            include_bytes!("../tests/amazon/r4m04.crl"),
            include_bytes!("../tests/amazon/e2m01.crl"),
            include_bytes!("../tests/amazon/e2m02.crl"),
            include_bytes!("../tests/amazon/e2m03.crl"),
            include_bytes!("../tests/amazon/e2m04.crl"),
            include_bytes!("../tests/amazon/e3m01.crl"),
            include_bytes!("../tests/amazon/e3m02.crl"),
            include_bytes!("../tests/amazon/e3m03.crl"),
            include_bytes!("../tests/amazon/e3m04.crl"),
        ];

        CRL_DER
            .iter()
            .copied()
            .map(OwnedCertRevocationList::from_der)
            .map(Result::unwrap)
            .map(CertRevocationList::from)
            .collect()
    }
}
