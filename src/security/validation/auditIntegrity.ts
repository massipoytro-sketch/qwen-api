export type AuditLink = {
  requestId: string;
  decisionId: string;
  assessmentId: string;
  enforcementId: string;
  auditId: string;
};

export function validateAuditChain(link: AuditLink): string[] {
  const failures: string[] = [];
  for (const [name, value] of Object.entries(link)) {
    if (!value || value.length > 256) failures.push(`${name}_invalid`);
  }
  if (new Set(Object.values(link)).size !== 5) failures.push("duplicate_chain_reference");
  return failures;
}

export function validateAuditCompleteness(input: {
  decisionExists: boolean;
  enforcementExists: boolean;
  transactionCommitted: boolean;
  auditExists: boolean;
  controlChange: boolean;
  controlAuditExists: boolean;
}): string[] {
  const failures: string[] = [];
  if (input.transactionCommitted && (!input.decisionExists || !input.enforcementExists)) failures.push("commit_without_security_chain");
  if (input.transactionCommitted && !input.auditExists) failures.push("commit_without_audit");
  if (input.controlChange && !input.controlAuditExists) failures.push("control_change_without_audit");
  return failures;
}
