//! W7 template expansion (AR13): `${VAR}` references resolved at USE time
//! (run, or cat --expand); the repo always stores the raw text — pull
//! restores files exactly as committed, without expansion. Strict by
//! decision: an unresolved reference or a cycle is a hard error naming the
//! variable — templates never fail silently.

use std::collections::BTreeMap;

use crate::error::LatchError;

/// Expand every value in the map against the map itself.
pub fn expand_all(vars: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>, LatchError> {
    let mut out = BTreeMap::new();
    for key in vars.keys() {
        let mut seen = Vec::new();
        out.insert(key.clone(), resolve(key, vars, &mut seen)?);
    }
    Ok(out)
}

fn resolve(
    key: &str,
    vars: &BTreeMap<String, String>,
    seen: &mut Vec<String>,
) -> Result<String, LatchError> {
    if seen.iter().any(|s| s == key) {
        return Err(LatchError::other(
            format!("template cycle: {} -> {}", seen.join(" -> "), key),
            "break the cycle — a variable may not (indirectly) reference itself",
        ));
    }
    seen.push(key.to_string());
    let raw = vars.get(key).ok_or_else(|| {
        LatchError::other(
            format!("template references undefined variable ${{{}}}", key),
            "define it in an env file of this project/environment, or fix the typo",
        )
    })?;
    let result = expand_str(raw, vars, seen)?;
    seen.pop();
    Ok(result)
}

/// Expand `${NAME}` occurrences in one string.
pub fn expand_str(
    raw: &str,
    vars: &BTreeMap<String, String>,
    seen: &mut Vec<String>,
) -> Result<String, LatchError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return Err(LatchError::other(
                format!("unterminated ${{ in '{}'", raw),
                "close the reference with }} or remove the ${{",
            ));
        };
        let name = &after[..end];
        out.push_str(&resolve(name, vars, seen)?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn chains_expand() {
        let vars = map(&[
            ("DB_HOST", "10.0.0.5"),
            ("DB_PASS", "hunter2"),
            ("DATABASE_URL", "postgres://u:${DB_PASS}@${DB_HOST}/app"),
        ]);
        let out = expand_all(&vars).unwrap();
        assert_eq!(out["DATABASE_URL"], "postgres://u:hunter2@10.0.0.5/app");
    }

    #[test]
    fn undefined_reference_is_named() {
        let vars = map(&[("A", "${TYPO}")]);
        let err = expand_all(&vars).unwrap_err();
        assert!(format!("{err}").contains("TYPO"), "{err}");
    }

    #[test]
    fn cycles_are_named() {
        let vars = map(&[("A", "${B}"), ("B", "${A}")]);
        let err = expand_all(&vars).unwrap_err();
        assert!(format!("{err}").contains("cycle"), "{err}");
    }

    #[test]
    fn unterminated_is_an_error() {
        let vars = map(&[("A", "${OOPS")]);
        assert!(expand_all(&vars).is_err());
    }
}
