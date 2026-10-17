import { describe, expect, it } from "vitest";
import { validateAuditChain, validateAuditCompleteness } from "../src/security/validation/auditIntegrity";

describe("Part 5F audit integrity", () => {
  it("requires unique references across the security chain", () => {
    expect(validateAuditChain({
      requestId: "req-1",
      decisionId: "decision-1",
      assessmentId: "assessment-1",
      enforcementId: "enforcement-1",
      auditId: "audit-1",
    })).toEqual([]);

    expect(validateAuditChain({
      requestId: "same",
      decisionId: "same",
      assessmentId: "assessment-1",
      enforcementId: "enforcement-1",
      auditId: "audit-1",
    })).toContain("duplicate_chain_reference");
  });

  it("rejects commits without the complete security chain", () => {
    expect(validateAuditCompleteness({
      decisionExists: false,
      enforcementExists: false,
      transactionCommitted: true,
      auditExists: true,
      controlChange: false,
      controlAuditExists: false,
    })).toEqual(["commit_without_security_chain"]);
  });

  it("requires a dedicated audit for global control changes", () => {
    expect(validateAuditCompleteness({
      decisionExists: true,
      enforcementExists: true,
      transactionCommitted: false,
      auditExists: false,
      controlChange: true,
      controlAuditExists: false,
    })).toEqual(["control_change_without_audit"]);
  });
});
