//! How domain names typed by the user are encoded into labels.
//!
//! These pin the behaviour of the IDNA library dog has always used, so that
//! replacing that library cannot quietly change which names dog accepts or
//! what it sends for them.

use dns::Labels;

fn encode(input: &str) -> Result<String, String> {
    Labels::encode(input).map(|labels| labels.to_string()).map_err(str::to_owned)
}

#[cfg(feature = "with_idna")]
#[test]
fn idna_encoding() {
    let max_label = "a".repeat(63);
    let long_label = "a".repeat(64);

    let cases: Vec<(&str, Result<String, String>)> = vec![
        ("example.com", Ok("example.com.".into())),
        ("example.com.", Ok("example.com.".into())),
        ("a..b", Ok("a.b.".into())),
        ("EXAMPLE.Com", Ok("example.com.".into())),
        ("_dmarc.example.com", Ok("_dmarc.example.com.".into())),
        ("_25._tcp.mail.example", Ok("_25._tcp.mail.example.".into())),
        ("bücher.example", Ok("xn--bcher-kva.example.".into())),
        ("BÜCHER.example", Ok("xn--bcher-kva.example.".into())),
        ("xn--bcher-kva.example", Ok("xn--bcher-kva.example.".into())),
        ("faß.example", Ok("xn--fa-hia.example.".into())),
        ("☕.example", Ok("xn--53h.example.".into())),
        ("ab--cd.example", Ok("ab--cd.example.".into())),
        ("-lead.example", Err("-lead".into())),
        ("trail-.example", Err("trail-".into())),
        ("xn--zz.example", Err("xn--zz".into())),
        (max_label.as_str(), Ok(format!("{max_label}."))),
        (long_label.as_str(), Err(long_label.clone())),
    ];

    for (input, expected) in cases {
        assert_eq!(encode(input), expected, "{input:?}");
    }
}

#[cfg(not(feature = "with_idna"))]
#[test]
fn without_idna_names_pass_through() {
    assert_eq!(encode("bücher.example"), Ok("bücher.example.".into()));
    assert_eq!(encode("EXAMPLE.com"), Ok("EXAMPLE.com.".into()));
    assert_eq!(encode(&"a".repeat(64)), Ok(format!("{}.", "a".repeat(64))));
    assert_eq!(encode(&"a".repeat(256)), Err("a".repeat(256)));
}
