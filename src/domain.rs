// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

pub fn normalize_domain_rule(value: &str) -> Result<String, String> {
    normalize_domain_name(value).ok_or_else(|| {
        format!(
            "invalid domain `{value}`; expected a DNS name like `example.com` or `api.example.com`"
        )
    })
}

pub fn normalize_domain_name(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }

    let normalized = trimmed.to_ascii_lowercase();
    let labels = normalized.split('.').collect::<Vec<_>>();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }

    Some(normalized)
}

pub fn matches_domain_rule(qname: &str, rule: &str) -> bool {
    qname == rule
        || (qname.len() > rule.len()
            && qname.ends_with(rule)
            && qname.as_bytes()[qname.len() - rule.len() - 1] == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_rule_lowercases_and_strips_trailing_dot() {
        assert_eq!(
            normalize_domain_rule("API.Example.COM.").unwrap(),
            "api.example.com"
        );
    }

    #[test]
    fn normalize_domain_rule_rejects_invalid_values() {
        assert!(normalize_domain_rule("").is_err());
        assert!(normalize_domain_rule("exa mple.com").is_err());
        assert!(normalize_domain_rule("-example.com").is_err());
    }

    #[test]
    fn matches_domain_rule_accepts_exact_and_subdomain_matches() {
        assert!(matches_domain_rule("example.com", "example.com"));
        assert!(matches_domain_rule("api.example.com", "example.com"));
        assert!(!matches_domain_rule("badexample.com", "example.com"));
    }
}
