//! `rf.finding/1` records and their text and JSON Lines renderings.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA: &str = "rf.finding/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub path: String,
    pub locator: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub schema: String,
    pub tool: String,
    pub rule: String,
    pub severity: Severity,
    pub subject: String,
    pub message: String,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
    pub at: String,
}

impl Finding {
    pub fn new(
        rule: &str,
        severity: Severity,
        subject: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Finding {
            schema: SCHEMA.to_owned(),
            tool: "prov".to_owned(),
            rule: rule.to_owned(),
            severity,
            subject: subject.into(),
            message: message.into(),
            evidence: Vec::new(),
            data: Value::Null,
            at: crate::now_rfc3339(),
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }

    pub fn with_evidence(mut self, path: impl Into<String>, locator: impl Into<String>) -> Self {
        self.evidence.push(Evidence {
            path: path.into(),
            locator: locator.into(),
        });
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Format {
    #[default]
    Text,
    Jsonl,
}

/// The findings one command produced, in emission order.
#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn extend(&mut self, findings: impl IntoIterator<Item = Finding>) {
        self.findings.extend(findings);
    }

    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }

    pub fn count(&self, rule: &str) -> usize {
        self.findings.iter().filter(|f| f.rule == rule).count()
    }

    pub fn emit(&self, format: Format, out: &mut dyn Write) -> io::Result<()> {
        for finding in &self.findings {
            match format {
                Format::Jsonl => {
                    serde_json::to_writer(&mut *out, finding)?;
                    out.write_all(b"\n")?;
                }
                Format::Text => write_text(finding, out)?,
            }
        }
        out.flush()
    }
}

pub fn write_text(finding: &Finding, out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "{:<5} {} {}: {}",
        finding.severity.label(),
        finding.rule,
        finding.subject,
        finding.message
    )?;
    for e in &finding.evidence {
        writeln!(out, "      at {} ({})", e.path, e.locator)?;
    }
    Ok(())
}
