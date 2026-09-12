function levelFor(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

export function toSarif(report) {
  const rules = report.findings.map((f) => ({
    id: f.id,
    shortDescription: { text: f.title },
    fullDescription: { text: f.remediation || f.title },
    help: { text: f.remediation || "Review the finding and validate it in context." },
    properties: {
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      standard: f.standard
    }
  }));
  const uniqueRules = [...new Map(rules.map((r) => [r.id, r])).values()];
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
