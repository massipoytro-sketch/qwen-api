import { describe, expect, it } from "vitest";
import { evaluateControlPlane, validateControlTransition, validateRevocation } from "../src/security/controlPlane";

const active = {
  globalMode: "normal" as const, tenantMode: "normal" as const, subjectMode: "normal" as const,
  sessionStatus: "active" as const, loadedAt: "2026-10-17T10:00:00.000Z", version: 1,
};

describe("Part 5E control plane", () => {
  it("fails closed when control state is missing or stale", () => {
    expect(evaluateControlPlane({ snapshot: null, now: Date.parse(active.loadedAt) }).decisionFloor).toBe("BLOCK");
    expect(evaluateControlPlane({ snapshot: active, now: Date.parse(active.loadedAt) + 6000 }).reasonCodes).toContain("CONTROL_PLANE_UNAVAILABLE");
  });
  it("global lockdown dominates tenant normal", () => {
    expect(evaluateControlPlane({ snapshot: { ...active, globalMode: "lockdown" }, now: Date.parse(active.loadedAt) }).decisionFloor).toBe("BLOCK");
  });
  it("review-only cannot be weakened by a normal tenant", () => {
    expect(evaluateControlPlane({ snapshot: { ...active, globalMode: "review_only" }, now: Date.parse(active.loadedAt) }).decisionFloor).toBe("REVIEW");
  });
  it("rejects revoked sessions and subject blocks", () => {
    expect(evaluateControlPlane({ snapshot: { ...active, sessionStatus: "revoked" }, now: Date.parse(active.loadedAt) }).reasonCodes).toContain("SESSION_REVOKED");
    expect(evaluateControlPlane({ snapshot: { ...active, subjectMode: "block" }, now: Date.parse(active.loadedAt) }).decisionFloor).toBe("BLOCK");
  });
  it("rejects unauthorized transitions and downgrade", () => {
    expect(() => validateControlTransition({ current: "normal", requested: "lockdown", authorized: false, incidentReason: "incident test" })).toThrow("CONTROL_PLANE_UNAUTHORIZED");
    expect(() => validateControlTransition({ current: "lockdown", requested: "normal", authorized: true, incidentReason: "incident recovery" })).toThrow("CONTROL_PLANE_DOWNGRADE_REQUIRES_RECOVERY_APPROVAL");
  });
  it("requires tenant scope and actor authorization for revocation", () => {
    expect(() => validateRevocation({ tenantId: "00000000-0000-4000-8000-000000000001", sessionId: "00000000-0000-4000-8000-000000000002", reasonCode: "INCIDENT_REVOKE", actorId: "operator", authorized: false })).toThrow("SESSION_REVOCATION_UNAUTHORIZED");
  });
});
