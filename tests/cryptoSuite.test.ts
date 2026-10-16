import { describe, expect, it } from "vitest";
import {
  deriveP384SharedKey,
  encryptString,
  decryptString,
  generateAes256Key,
  generateEcdsa384KeyPair,
  generateP384KeyPair,
  sha384,
  sha512,
  signEcdsa384,
  verifyEcdsa384,
} from "../src/security/cryptoSuite";

describe("cryptographic trust suite", () => {
  it("encrypts and authenticates data with AES-256-GCM", () => {
    const key = generateAes256Key();
    const envelope = encryptString("gainiren-secret", key, "k-2026-01", "tenant:test");
    expect(envelope.algorithm).toBe("aes-256-gcm");
    expect(envelope.keyId).toBe("k-2026-01");
    expect(decryptString(envelope, key)).toBe("gainiren-secret");
    expect(() => decryptString({ ...envelope, ciphertext: envelope.ciphertext.slice(0, -1) + "A" }, key)).toThrow();
    expect(() => decryptString(envelope, generateAes256Key())).toThrow();
  });

  it("binds AES-256-GCM ciphertext to AAD", () => {
    const key = generateAes256Key();
    const envelope = encryptString("bound", key, "k1", "tenant-a");
    expect(decryptString(envelope, key, "tenant-a")).toBe("bound");
    expect(() => decryptString(envelope, key, "tenant-b")).toThrow();
  });

  it("derives the same P-384 ECDH key on both sides", () => {
    const alice = generateP384KeyPair();
    const bob = generateP384KeyPair();
    const aliceShared = deriveP384SharedKey(alice.privateKey, bob.publicKey, Buffer.from("salt"));
    const bobShared = deriveP384SharedKey(bob.privateKey, alice.publicKey, Buffer.from("salt"));
    expect(alice.publicKey.length).toBe(97);
    expect(alice.privateKey.length).toBe(48);
    expect(aliceShared.equals(bobShared)).toBe(true);
    expect(aliceShared.length).toBe(32);
  });

  it("signs and verifies with ECDSA P-384 / SHA-384", () => {
    const keys = generateEcdsa384KeyPair();
    const payload = "security-decision|tenant=synthetic|nonce=unique";
    const signature = signEcdsa384(payload, keys.privateKeyPem);
    expect(verifyEcdsa384(payload, signature, keys.publicKeyPem)).toBe(true);
    expect(verifyEcdsa384(`${payload}|tampered`, signature, keys.publicKeyPem)).toBe(false);
  });

  it("produces SHA-384 and SHA-512 fingerprints", () => {
    expect(sha384("gainiren")).toHaveLength(96);
    expect(sha512("gainiren")).toHaveLength(128);
    expect(sha384("a")).not.toBe(sha384("b"));
  });
});
