
pub type Signature<const N: usize> = [(u8, bool); N];

pub const fn calc_signature_size(s: &[u8]) -> usize {
    let mut len = 0usize;
    let mut i = 0usize;
    let mut last_was_space = true;
    while i < s.len() {
        let is_space = s[i] == b' ';
        if is_space != last_was_space {
            if !is_space {
                len += 1;
            }
            last_was_space = is_space;
        }
        i += 1;
    }
    len
}

pub const fn parse_hex_digit(c: u8) -> u8 {
    if c >= b'0' && c <= b'9' { c - b'0' }
    else if c >= b'a' && c <= b'f' { c - b'a' + 10 }
    else if c >= b'A' && c <= b'F' { c - b'A' + 10 }
    else {
        panic!("hex digit expected");
    }
}

pub const fn craft_signature<const N: usize>(s: &[u8]) -> Signature<N> {
    let mut current = (0u8, false);
    let mut bytes = [current; N];
    let mut i = 0usize;
    let mut sig_i = 0usize;
    let mut last_was_space = true;
    while i < s.len() {
        let is_space = s[i] == b' ';
        if is_space != last_was_space {
            if is_space {
                bytes[sig_i] = current;
                current = (0u8, false);
                sig_i += 1;
            }
            last_was_space = is_space;
        }
        if !is_space {
            let is_wildcard = s[i] == b'?';
            assert!(current.0 <= 0xF, "hex value <= 0xFF expected");
            assert!(!current.1 || is_wildcard, "'?' expected");
            if is_wildcard {
                current.1 = true;
            } else {
                current.0 = current.0 << 4 | parse_hex_digit(s[i]);
            }
        }
        i += 1;
    }
    if !last_was_space {
        bytes[sig_i] = current;
    }
    bytes
}

#[macro_export]
macro_rules! define_signature {
    ($s:literal) => {
        {
            use crate::aob;

            const SIG_LEN: usize = aob::calc_signature_size($s);
            const SIG: aob::Signature<SIG_LEN> = aob::craft_signature::<SIG_LEN>($s);
            SIG.as_slice()
        }
    };
}