//! Case-scoped, bounded search for portable artifact and finding summaries.
//! Never returns absolute stored paths or unbounded raw evidence content.
use crate::{ArtifactStore, ReportArtifact};
use rusqlite::params;
use serde::{Deserialize, Serialize};

const MAX_PAGE_SIZE: usize = 100;
const MAX_OFFSET: usize = 100_000;

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchFinding {
    pub id: i64,
    pub source: String,
    pub title: String,
    pub severity: String,
    pub artifact_id: Option<String>,
    pub created_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseSearchPage {
    pub case_id: String,
    pub artifacts: Vec<ReportArtifact>,
    pub findings: Vec<SearchFinding>,
    pub truncated_artifacts: bool,
    pub truncated_findings: bool,
}

fn literal_like_query(term: &str) -> Result<String, String> {
    let query = term.trim();
    if query.is_empty() || query.len() > 200 || query.chars().any(char::is_control) {
        return Err("invalid case search query".into());
    }
    let mut escaped = String::with_capacity(query.len() + 2);
    escaped.push('%');
    for c in query.chars() {
        if matches!(c, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped.push('%');
    Ok(escaped)
}

impl ArtifactStore {
    /// Search only the selected existing case, using a bounded read and a
    /// deterministic cursor-like (limit, offset) window.
    pub fn search_case(
        &self,
        case_id: &str,
        query: &str,
        limit: usize,
        offset: usize,
    ) -> Result<CaseSearchPage, String> {
        crate::validate_case_id(case_id)?;
        if !self.case_exists(case_id)? {
            return Err("case not found".into());
        }
        if limit == 0 || limit > MAX_PAGE_SIZE || offset > MAX_OFFSET {
            return Err("invalid case search page bounds".into());
        }
        let needle = literal_like_query(query)?;
        let fetched = (limit + 1) as i64;
        let offset = offset as i64;

        let mut a_stmt = self
            .conn
            .prepare(
                "SELECT id,name,size,sha256,signature,imported_at
             FROM artifacts
             WHERE case_id=?1 AND (name LIKE ?2 ESCAPE '\\' OR id LIKE ?2 ESCAPE '\\')
             ORDER BY id ASC LIMIT ?3 OFFSET ?4",
            )
            .map_err(|e| e.to_string())?;
        let a_rows = a_stmt
            .query_map(params![case_id, needle, fetched, offset], |r| {
                Ok(ReportArtifact {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    size: r.get::<_, i64>(2)?.max(0) as u64,
                    sha256: r.get(3)?,
                    signature: r.get(4)?,
                    imported_at: r.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut artifacts = a_rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let truncated_artifacts = artifacts.len() > limit;
        artifacts.truncate(limit);

        let mut f_stmt = self
            .conn
            .prepare(
                "SELECT id,source,title,severity,artifact_id,created_ms
             FROM findings
             WHERE case_id=?1 AND
               (title LIKE ?2 ESCAPE '\\' OR details LIKE ?2 ESCAPE '\\'
                OR source LIKE ?2 ESCAPE '\\')
             ORDER BY id ASC LIMIT ?3 OFFSET ?4",
            )
            .map_err(|e| e.to_string())?;
        let f_rows = f_stmt
            .query_map(params![case_id, needle, fetched, offset], |r| {
                Ok(SearchFinding {
                    id: r.get(0)?,
                    source: r.get(1)?,
                    title: r.get(2)?,
                    severity: r.get(3)?,
                    artifact_id: r.get(4)?,
                    created_ms: r.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut findings = f_rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let truncated_findings = findings.len() > limit;
        findings.truncate(limit);

        Ok(CaseSearchPage {
            case_id: case_id.to_owned(),
            artifacts,
            findings,
            truncated_artifacts,
            truncated_findings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactRecord, NewFinding, DEFAULT_CASE};

    fn artifact(id: &str, case_id: &str, name: &str) -> ArtifactRecord {
        ArtifactRecord {
            id: id.into(),
            case_id: case_id.into(),
            name: name.into(),
            stored_path: "/private/excluded".into(),
            original_path: Some("/private/original".into()),
            size: 2,
            sha256: "b".repeat(64),
            md5: String::new(),
            sha1: String::new(),
            crc32: String::new(),
            signature: None,
            entropy: 0.0,
            imported_at: "1".into(),
        }
    }

    #[test]
    fn literal_wildcards_bound_pagination_and_never_include_host_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&tmp.path().join("db.sqlite")).unwrap();
        let other = store.create_case("Other", "").unwrap();
        for (id, name) in [
            ("first", "capture_%a"),
            ("second", "capture_%b"),
            ("third", "capture_a"),
        ] {
            store
                .upsert_artifact(&artifact(id, DEFAULT_CASE, name))
                .unwrap();
        }
        store
            .upsert_artifact(&artifact("elsewhere", &other.id, "capture_%a"))
            .unwrap();
        store
            .add_findings(
                DEFAULT_CASE,
                "scanner",
                None,
                &[NewFinding {
                    title: "capture_% record".into(),
                    severity: "info".into(),
                    details: "matches literal wildcard".into(),
                }],
            )
            .unwrap();
        let result = store.search_case(DEFAULT_CASE, "capture_%", 1, 0).unwrap();
        assert_eq!(result.artifacts.len(), 1);
        assert!(result.truncated_artifacts);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.artifacts[0].id, "first");
        let next = store.search_case(DEFAULT_CASE, "capture_%", 1, 1).unwrap();
        assert_eq!(next.artifacts[0].id, "second");
        assert!(!next.truncated_artifacts);
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("/private"));
        assert!(
            store
                .search_case(&other.id, "capture_%", 100, 0)
                .unwrap()
                .artifacts
                .len()
                == 1
        );
        assert!(store
            .search_case(DEFAULT_CASE, "capture_%", 101, 0)
            .is_err());
        // A literal '%' matches only names that contain '%', not all rows.
        assert_eq!(
            store
                .search_case(DEFAULT_CASE, "%", 100, 0)
                .unwrap()
                .artifacts
                .len(),
            2
        );
    }
}
