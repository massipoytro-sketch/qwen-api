import { createHash } from "node:crypto";

export const hashValue = (value: string) =>
  createHash("sha256").update(value, "utf8").digest("hex");
