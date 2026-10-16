import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { constantTimeHexEqual, createRotatingRequestNonce, decryptAes256Gcm, deriveP384SharedSecret, encryptAes256Gcm, generateP384KeyPair, hmacSha256Hex, sha384Hex, sha512Hex, signP384Sha384, verifyP384Sha384, verifySignedRequest, canonicalSignedRequest } from "../src/security/cryptoTrust";

describe("cryptographic trust primitives", () => {
  it("encrypts and authenticates data with AES-256-GCM", () => {
    const key = randomBytes(32);
    const aad = Buffer.from("gainiren-security-v1");
    const encrypted = encryptAes256Gcm("secret-evidence", key, aad);
    expect(encrypted.algorithm).toBe("AES-256-GCM");
    expect(decryptAes256Gcm({ ...encrypted, key, aad }).toString()).toBe("secret-evidence");
    expect(() => decryptAes256Gcm({ ...encrypted, key, aad: Buffer.from("wrong") })).toThrow();
  });

  it("binds a request signature to timestamp, nonce, body hash and key id", () => {
    const secret = randomBytes(32);
    const body = JSON.stringify({ action: "withdrawal", amount: 100 });
    const timestamp = Date.now();
    const nonce = createRotatingRequestNonce();
    const keyId = "key-2026-10";
    const bodyHash = sha384Hex(body);
    const canonical = canonicalSignedRequest({ method: "POST", path: "/api/security-check", timestamp, nonce, bodyHash, keyId });
    const signature = hmacSha256Hex(secret, canonical);
    const request = { keyId, timestamp, nonce, bodyHash, signature };
    expect(verifySignedRequest({ request, method: "POST", path: "/api/security-check", body, secret, nowMs: timestamp })).toBe(true);
    expect(verifySignedRequest({ request, method: "POST", path: "/api/security-check", body: body + "!", secret, nowMs: timestamp })).toBe(false);
    expect(verifySignedRequest({ request, method: "POST", path: "/api/security-check", body, secret, nowMs: timestamp + 6 * 60_000 })).toBe(false);
    expect(constantTimeHexEqual(signature, "0".repeat(64))).toBe(false);
  });

  it("supports P-384 ECDH shared-secret agreement", () => {
    const alice = generateP384KeyPair();
    const bob = generateP384KeyPair();
    expect(deriveP384SharedSecret(alice.privateKey, bob.publicKey).equals(deriveP384SharedSecret(bob.privateKey, alice.publicKey))).toBe(true);
  });

  it("supports SHA-384/SHA-512 and ECDSA P-384/SHA-384 signatures", () => {
    const message = "gainiren-active-defense";
    expect(sha384Hex(message)).toHaveLength(96);
    expect(sha512Hex(message)).toHaveLength(128);
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "secp384r1" });
    const privatePem = createPrivateKey(privateKey).export({ type: "pkcs8", format: "pem" }).toString();
    const publicPem = createPublicKey(publicKey).export({ type: "spki", format: "pem" }).toString();
    const signature = signP384Sha384(privatePem, message);
    expect(verifyP384Sha384(publicPem, message, signature)).toBe(true);
    expect(verifyP384Sha384(publicPem, message + "!", signature)).toBe(false);
  });
});
