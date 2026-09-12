const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

// Several findings can share one rule id (one per cookie, for example). The
// rule entry describes the rule, so it must not quote one arbitrary member's
// title, and its severity must be the highest any result reports.
function ruleDescription(finding) {
  return finding.category === "web-security" && finding.id.startsWith("cookie-")
    ? `Set-Cookie attribute issue: ${finding.id.replace("cookie-missing-", "missing ")}`
    : finding.title;
}

function mergeRule(existing, next) {
  if (!existing) return next;
  const worse = (SEVERITY_RANK[next.properties.severity] ?? 0) > (SEVERITY_RANK[existing.properties.severity] ?? 0);
  return worse ? next : existing;
}

function levelFor(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

export function toSarif(report) {
  const rules = report.findings.map((f) => ({
    id: f.id,
    shortDescription: { text: ruleDescription(f) },
    fullDescription: { text: f.remediation || ruleDescription(f) },
    help: { text: f.remediation || "Review the finding and validate it in context." },
    properties: {
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      standard: f.standard
    }
  }));
  const byId = new Map();
  for (const rule of rules) byId.set(rule.id, mergeRule(byId.get(rule.id), rule));
  const uniqueRules = [...byId.values()];
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "AgentSafe WebScan",
          version: report.scanner.version,
          informationUri: "https://github.com/keepiteinfach/agent-safe-webscan",
          rules: uniqueRules
        }
      },
      results: report.findings.map((f) => ({
        ruleId: f.id,
        level: levelFor(f.severity),
        message: { text: `${f.title}. ${f.evidence}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: report.target.finalUrl } } }],
        properties: {
          severity: f.severity,
          confidence: f.confidence,
          category: f.category,
          remediation: f.remediation
        }
      }))
    }]
  };
}
