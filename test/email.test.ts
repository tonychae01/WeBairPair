import { describe, expect, it } from "vitest";
import { createPairing, isBerkeleyEmail, normalizeEmail, pairKey } from "../src/index";

describe("Berkeley email validation", () => {
  it("normalizes casing and whitespace", () => {
    expect(normalizeEmail("  Oski@BERKELEY.EDU ")).toBe("oski@berkeley.edu");
  });

  it("accepts only the exact berkeley.edu domain", () => {
    expect(isBerkeleyEmail("oski@berkeley.edu")).toBe(true);
    expect(isBerkeleyEmail("oski@sub.berkeley.edu")).toBe(false);
    expect(isBerkeleyEmail("oski@berkeley.edu.example.com")).toBe(false);
    expect(isBerkeleyEmail("@berkeley.edu")).toBe(false);
  });
});

describe("pairing", () => {
  it("avoids every previous match when a fresh perfect matching exists", () => {
    const emails = ["a@berkeley.edu", "b@berkeley.edu", "c@berkeley.edu", "d@berkeley.edu"];
    const previous = new Set([
      pairKey(emails[0], emails[1]),
      pairKey(emails[2], emails[3]),
    ]);
    const result = createPairing(emails, previous);

    expect(result.pairs).toHaveLength(2);
    expect(result.pairs.every(([a, b]) => !previous.has(pairKey(a, b)))).toBe(true);
  });

  it("uses a repeat only when no all-new matching exists", () => {
    const emails = ["a@berkeley.edu", "b@berkeley.edu", "c@berkeley.edu", "d@berkeley.edu"];
    const onlyFreshPair = pairKey(emails[0], emails[1]);
    const previous = new Set<string>();
    for (let i = 0; i < emails.length; i++) {
      for (let j = i + 1; j < emails.length; j++) {
        if (pairKey(emails[i], emails[j]) !== onlyFreshPair) {
          previous.add(pairKey(emails[i], emails[j]));
        }
      }
    }
    const result = createPairing(emails, previous);
    const repeats = result.pairs.filter(([a, b]) => previous.has(pairKey(a, b)));

    expect(repeats).toHaveLength(1);
  });

  it("leaves exactly one person unmatched for an odd group", () => {
    const result = createPairing(
      ["a@berkeley.edu", "b@berkeley.edu", "c@berkeley.edu"],
      new Set(),
    );
    expect(result.pairs).toHaveLength(1);
    expect(result.unmatched).toBeDefined();
  });

  it("avoids leaving the most recently unmatched person out again", () => {
    const emails = ["a@berkeley.edu", "b@berkeley.edu", "c@berkeley.edu"];
    const lastUnmatched = new Map<string, string | null>([
      [emails[0], "2026-08-01T17:00:00.000Z"],
      [emails[1], null],
      [emails[2], "2026-01-01T17:00:00.000Z"],
    ]);
    const result = createPairing(emails, new Set(), lastUnmatched);

    expect(result.unmatched).toBe(emails[1]);
  });
});
