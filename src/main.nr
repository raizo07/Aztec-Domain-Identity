#[dep::aztec::macros::aztec]
pub contract Main {
    use dep::aztec::macros::{functions::{initializer, public}, storage::storage};
    use std::hash::pedersen_hash;
    use std::meta::derive;
    use dep::aztec::prelude::{Map, PublicMutable};
    use dep::aztec::protocol_types::traits::{Deserialize, Packable, Serialize}; // TODO `impl ToField` instead of `pedersen_hash` hashing each time

    /// FQDN specified max. len. minus the _domaindkim_ specified part minus minimum selector can take
    global FQDN_LEN_MAX: u32 = 253 - 10 - 2;
    global DNSKEY_64_PACKED_LEN: u32 = 64 + 1 + FQDN_LEN_MAX;
    global DKIM_KEY_RSA2048_PACKED_LEN: u32 = 256 + 1 + FQDN_LEN_MAX + 1 + 63;
    // TODO make these normal constants instead of conversions
    global DKIM_LABEL: [u8; 10] = "_domainkey".as_bytes();
    global DOT_BYTE: u8 = ".".as_bytes()[0];

    type Fqdn = BoundedVec<u8, FQDN_LEN_MAX>;

    /// estimation of max length of a DNSKEY record, can be calculated precisely beyond the prototype #calculatonEstimation
    // The thing is RRSIG covers a whole RRset of the records of a type. The prototype handles only the kind of
    // setup which have a couple of DNSKEY; actually this already covers most of the setups. But there's some ways
    // to combine a big `RRset` from parts with enough development invested in this. A straight-forward solution
    // is to save tuples of records, iterate over those to get the digest, and wipe them.
    // [A recommended DNSKEY RRset length maximum is 13 but some systems allow much higher (which open those for an attack).](https://datatracker.ietf.org/meeting/121/materials/slides-121-dnsop-sessb-dns-upper-limit-values-00) */
    #[derive(Deserialize, Serialize)]
    pub struct Ec256DnskeyRecordSetBytes {
        bytes: BoundedVec<u8, 333 * 2>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct Ec256DsRecordSetBytes {
        bytes: BoundedVec<u8, 289 * 2>, // #calculatonEstimation
    }

    #[derive(Deserialize, Serialize)]
    pub struct DkimKeyRsa2048 {
        domain: Fqdn,
        selector: BoundedVec<u8, 63>,
        key: [u8; 256],
    }

    #[derive(Deserialize, Serialize)]
    pub struct DkimRecordRsa2048 {
        bytes: BoundedVec<u8, 263 + FQDN_LEN_MAX>, // #calculatonEstimation
    }

    #[derive(Deserialize, Serialize)]
    pub struct Bytes64DnsKey {
        domain: Fqdn,
        key_x: [u8; 32],
        key_y: [u8; 32],
        // TODO can a key tag be useful in the project?
    }

    /* TODO quite some space for optimization here
    it's really awful now, but with packed string this would be orders better */

    impl Packable<DNSKEY_64_PACKED_LEN> for Bytes64DnsKey {
        fn pack(self) -> [Field; DNSKEY_64_PACKED_LEN] {
            let l = self.domain.len();
            let mut r = [0; DNSKEY_64_PACKED_LEN - 64];
            for i in 0..l {
                r[i] = self.domain.get(i) as Field;
            }
            r[FQDN_LEN_MAX] = l as Field;

            r.concat(self.key_x.map(|b| b as Field)).concat(self.key_y.map(|b| b as Field))
        }
        fn unpack(packed: [Field; DNSKEY_64_PACKED_LEN]) -> Self {
            let mut d: [u8; FQDN_LEN_MAX] = [0; FQDN_LEN_MAX];
            let mut (key_x, key_y): ([u8; 32], [u8; 32]) = ([0; 32], [0; 32]);
            for i in 0..FQDN_LEN_MAX {
                d[i] = packed[i] as u8;
            }
            for i in 0..32 {
                key_x[i] = packed[i + FQDN_LEN_MAX + 1] as u8;
                key_y[i] = packed[i + FQDN_LEN_MAX + 1 + 32] as u8;
            }
            Bytes64DnsKey {
                domain: BoundedVec::from_parts_unchecked(d, packed[FQDN_LEN_MAX] as u32),
                key_x,
                key_y,
            }
        }
    }

    impl Packable<DKIM_KEY_RSA2048_PACKED_LEN> for DkimKeyRsa2048 {
        fn pack(self) -> [Field; DKIM_KEY_RSA2048_PACKED_LEN] {
            let l_domain = self.domain.len();
            let l_selector = self.selector.len();
            let mut r_domain = [0; FQDN_LEN_MAX + 1];
            for i in 0..l_domain {
                r_domain[i] = self.domain.get(i) as Field;
            }
            r_domain[FQDN_LEN_MAX] = l_domain as Field;
            let mut r_selector = [0; 63 + 1];
            for i in 0..l_selector {
                r_selector[i] = self.selector.get(i) as Field;
            }
            r_selector[63] = l_selector as Field;

            r_domain.concat(r_selector).concat(self.key.map(|b| b as Field))
        }
        fn unpack(packed: [Field; DKIM_KEY_RSA2048_PACKED_LEN]) -> Self {
            let mut d: [u8; FQDN_LEN_MAX] = [0; FQDN_LEN_MAX];
            let mut s: [u8; 63] = [0; 63];
            let mut key: [u8; 256] = [0; 256];
            for i in 0..FQDN_LEN_MAX {
                d[i] = packed[i] as u8;
            }
            for i in 0..63 {
                s[i] = packed[i + FQDN_LEN_MAX + 1] as u8;
            }
            for i in 0..256 {
                key[i] = packed[i + FQDN_LEN_MAX + 1 + 63 + 1] as u8;
            }
            DkimKeyRsa2048 {
                domain: BoundedVec::from_parts_unchecked(d, packed[FQDN_LEN_MAX] as u32),
                selector: BoundedVec::from_parts_unchecked(s, packed[FQDN_LEN_MAX + 1 + 63] as u32),
                key,
            }
        }
    }

    #[dep::aztec::macros::storage::storage]
    struct Storage<Context> {
        keysigkey: Map<
            Field,
            PublicMutable<
                bool, // is *not* revoked
                Context
            >,
            Context
        >,
        zonesigkey: Map<
            Field, // Bytes64DnsKey,
            PublicMutable<
                bool, // is *not* revoked
                Context
            >,
            Context
        >,
        dkimkey: Map<
            Field, // DkimKey,
            PublicMutable<
                // (
                    bool, // is *not* revoked
                    // Field, // no later
                    // Field, // not before
                // )
                Context
            >,
            Context
        >
    }

    /// Starting with the "com." KSK; when RSA
    /// verifier will be fixed it should be "." KSK here.
    #[public]
    #[initializer]
    fn initialize() {
        storage
            .keysigkey
            .at(pedersen_hash(Bytes64DnsKey {
                domain: BoundedVec::from_array("com.".as_bytes()),
                key_x: [
                    183 as u8, 31 as u8, 4 as u8, 101 as u8, 16 as u8, 29 as u8, 219 as u8,
                    226 as u8, 191 as u8, 12 as u8, 148 as u8, 85 as u8, 209 as u8, 47 as u8,
                    161 as u8, 108 as u8, 28 as u8, 218 as u8, 68 as u8, 244 as u8, 191 as u8,
                    27 as u8, 162 as u8, 85 as u8, 52 as u8, 24 as u8, 173 as u8, 31 as u8,
                    58 as u8, 169 as u8, 176 as u8, 105 as u8,
                ],
                key_y: [
                    115 as u8, 242 as u8, 27 as u8, 132 as u8, 235 as u8, 83 as u8, 44 as u8,
                    244 as u8, 3 as u8, 94 as u8, 232 as u8, 212 as u8, 131 as u8, 44 as u8,
                    162 as u8, 109 as u8, 137 as u8, 48 as u8, 106 as u8, 125 as u8, 50 as u8,
                    86 as u8, 12 as u8, 12 as u8, 176 as u8, 18 as u8, 157 as u8, 69 as u8,
                    10 as u8, 193 as u8, 8 as u8, 53 as u8,
                ],
            }
                .pack()))
            .write(true);
    }

    #[public]
    fn add_zsigk_len64_signed_ecdsap256sha256(
        ksigk: Bytes64DnsKey,
        domain_rrset_position: u32,
        ksigk_rrset_position: u32,
        rrset_dnskey: Ec256DnskeyRecordSetBytes,
        rrsig_dnskey: [u8; 64],
        zsigk_x: [u8; 32],
        zsigk_y: [u8; 32],
        zsigk_rrset_position: u32,
    ) {
        assert(
            storage.keysigkey.at(pedersen_hash(ksigk.pack())).read(),
            "the key has been revoked or never added",
        );

        let mut rrset_dnskey = rrset_dnskey;
        for i in 0..ksigk.domain.len() {
            rrset_dnskey.bytes.set_unchecked(domain_rrset_position + i, ksigk.domain.get(i));
        }
        for i in 0..32 {
            rrset_dnskey.bytes.set_unchecked(ksigk_rrset_position + i, ksigk.key_x[i]);
            rrset_dnskey.bytes.set_unchecked(ksigk_rrset_position + i + 32, ksigk.key_y[i]);
            rrset_dnskey.bytes.set_unchecked(zsigk_rrset_position + i, zsigk_x[i]);
            rrset_dnskey.bytes.set_unchecked(zsigk_rrset_position + i + 32, zsigk_y[i]);
        }

        assert(
            std::ecdsa_secp256r1::verify_signature(
                ksigk.key_x,
                ksigk.key_y,
                rrsig_dnskey,
                dep::sha256::sha256_var(
                    rrset_dnskey.bytes.storage(),
                    rrset_dnskey.bytes.len() as u64,
                ),
            ),
            "DNSKEY RRSIG signature verification failed",
        );

        storage
            .zonesigkey
            .at(pedersen_hash(Bytes64DnsKey { domain: ksigk.domain, key_x: zsigk_x, key_y: zsigk_y }
                .pack()))
            .write(true);
    }

    #[public]
    fn add_ksigk_len64_signed_ecdsap256sha256(
        parent_zsigk: Bytes64DnsKey,
        rrset_ds: Ec256DsRecordSetBytes,
        child_ksigk: Bytes64DnsKey,
        child_domain_position: u32,
        ksigk_rrset_position: u32,
        rrsig_ds: [u8; 64],
    ) {
        assert(
            storage.zonesigkey.at(pedersen_hash(parent_zsigk.pack())).read(),
            "the key has been revoked or never added",
        );

        let l_child = child_ksigk.domain.len();
        let l_parent = parent_zsigk.domain.len();
        // assert(".".as_bytes()[0] == child_ksigk.domain.get(l_child - l_parent), "DS must define a subdomain");
        let mut rrset_ds = rrset_ds;
        let child_prefix_len = l_child - l_parent;
        for i in 0..child_prefix_len {
            rrset_ds.bytes.set_unchecked(i + child_domain_position, child_ksigk.domain.get(i));
        }
        for i in 0..l_parent {
            rrset_ds.bytes.set_unchecked(
                i + child_domain_position + child_prefix_len,
                parent_zsigk.domain.get(i),
            );
        }
        for i in 0..32 {
            rrset_ds.bytes.set_unchecked(ksigk_rrset_position + i, child_ksigk.key_x[i]);
            rrset_ds.bytes.set_unchecked(ksigk_rrset_position + i + 32, child_ksigk.key_y[i]);
        }

        assert(
            std::ecdsa_secp256r1::verify_signature(
                parent_zsigk.key_x,
                parent_zsigk.key_y,
                rrsig_ds,
                dep::sha256::sha256_var(rrset_ds.bytes.storage(), rrset_ds.bytes.len() as u64),
            ),
            "DS RRSIG signature verification failed",
        );

        storage.keysigkey.at(pedersen_hash(child_ksigk.pack())).write(true);
    }

    #[public]
    fn add_dkim_rsa2048_signed_ecdsap256sha256(
        parts: DkimKeyRsa2048,
        record: DkimRecordRsa2048,
        dkim_key_position: u32,
        rrsig: [u8; 64],
        zsigk_x: [u8; 32],
        zsigk_y: [u8; 32],
    ) {
        assert(
            storage
                .zonesigkey
                .at(pedersen_hash(Bytes64DnsKey { domain: parts.domain, key_x: zsigk_x, key_y: zsigk_y }
                    .pack()))
                .read(),
            "the zone signing key has been revoked or never added",
        );

        let mut record = record.bytes;
        let l_selector = parts.selector.len();
        for i in 0..l_selector {
            record.set_unchecked(i, parts.selector.get_unchecked(i));
        }
        record.set_unchecked(l_selector, DOT_BYTE);
        for i in 0..10 {
            record.set_unchecked(i + l_selector + 1, DKIM_LABEL[i]);
        }
        record.set_unchecked(l_selector + 1 + 10, DOT_BYTE);
        for i in 0..parts.domain.len() {
            record.set_unchecked(i + l_selector + 1 + 10 + 1, parts.domain.get(i));
        }
        for i in 0..256 {
            record.set_unchecked(i + dkim_key_position, parts.key[i]);
        }

        assert(
            std::ecdsa_secp256r1::verify_signature(
                zsigk_x,
                zsigk_y,
                rrsig,
                dep::sha256::sha256_var(record.storage(), record.len() as u64),
            ),
            "DKIM RRSIG signature verification failed",
        );

        storage.dkimkey.at(pedersen_hash(parts.pack())).write(true);
    }

    #[public]
    fn check_rsa2048(the: DkimKeyRsa2048) {
        assert(
            storage.dkimkey.at(pedersen_hash(the.pack())).read(),
            "the DKIM key has been revoked or never added",
        );
    }
}

#[test]
fn test_paypalcom_pp_ndash_dkim1_txt() {
    assert(std::ecdsa_secp256r1::verify_signature(
        [
            63, 205, 154, 30, 253, 187, 190, 55, 132, 12, 194, 84, 134, 245, 60, 127, 77, 150, 247,
            245, 158, 110, 91, 47, 124, 192, 139, 251, 44, 12, 16, 152,
        ],
        [
            3, 255, 220, 108, 69, 43, 105, 56, 152, 89, 11, 209, 48, 103, 137, 208, 6, 195, 252,
            174, 80, 57, 174, 28, 151, 101, 240, 92, 129, 207, 59, 238,
        ],
        [
            133, 3, 79, 178, 129, 65, 2, 67, 119, 121, 165, 221, 220, 168, 254, 139, 229, 14, 138,
            199, 185, 203, 214, 105, 252, 73, 216, 223, 47, 213, 33, 17, 40, 67, 22, 254, 64, 169,
            83, 144, 131, 79, 44, 126, 28, 103, 221, 246, 253, 57, 66, 124, 94, 234, 91, 47, 79,
            204, 187, 66, 116, 248, 80, 3,
        ],
        [
            190, 104, 21, 63, 5, 38, 46, 193, 97, 171, 69, 178, 157, 245, 203, 13, 99, 150, 97, 252,
            242, 185, 185, 207, 130, 121, 103, 47, 81, 243, 19, 55,
        ],
    ));
}

#[test]
fn test_ecdsa_com_dnskey() {
    assert(std::ecdsa_secp256r1::verify_signature(
        [
            183, 31, 4, 101, 16, 29, 219, 226, 191, 12, 148, 85, 209, 47, 161, 108, 28, 218, 68,
            244, 191, 27, 162, 85, 52, 24, 173, 31, 58, 169, 176, 105,
        ],
        [
            115, 242, 27, 132, 235, 83, 44, 244, 3, 94, 232, 212, 131, 44, 162, 109, 137, 48, 106,
            125, 50, 86, 12, 12, 176, 18, 157, 69, 10, 193, 8, 53,
        ],
        [
            40, 4, 14, 209, 3, 30, 39, 182, 205, 32, 153, 102, 68, 4, 4, 132, 22, 49, 92, 23, 170,
            229, 202, 1, 220, 28, 115, 184, 93, 60, 190, 131, 7, 139, 125, 206, 153, 177, 111, 218,
            116, 239, 233, 28, 125, 232, 107, 251, 220, 79, 24, 150, 238, 245, 133, 83, 224, 105,
            154, 192, 149, 2, 56, 235,
        ],
        [
            144, 246, 38, 118, 139, 81, 41, 183, 88, 81, 151, 57, 40, 52, 222, 50, 229, 112, 139,
            75, 134, 246, 227, 200, 175, 30, 32, 88, 4, 32, 197, 56,
        ],
    ));
}
