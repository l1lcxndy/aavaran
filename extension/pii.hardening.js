'use strict';

(function (root) {
  // Shape-only rules, after the checksum rules: on the redaction path a miss costs more than a false hit.

  const GROUPED_RULES = [
    {
      // 3-5 groups of 4 digits: unvalidated Aadhaar, spaced card, spaced
      // account number. Covers 1234 5678 9012 and 4111-1111-1111-1111.
      kind: 'GROUPED_ID',
      re: /\b\d{4}(?:[\s\-]\d{4}){2,4}\b/g,
      normalize: (s) => s.replace(/\D/g, ''),
    },
    {
      // 12 digits in any grouping that failed Verhoeff. Still an Aadhaar
      // shape; still redacted; just not given an AADHAAR token, because we
      // cannot assert what we could not verify.
      kind: 'AADHAAR_SUSPECT',
      re: /\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
      normalize: (s) => s.replace(/\D/g, ''),
    },
    {
      // Masked forms. Invisible to every checksum rule because they are not
      // numbers: XXXX XXXX XXXX 4291, ****1234, •••• 5678
      kind: 'MASKED_ID',
      re: /(?:[xX*•●]{2,}[\s\-]?){2,}\d{2,}|\d{2,}[\s\-]?(?:[xX*•●]{2,}[\s\-]?){2,}/g,
    },
    {
      // 6-8 digit runs are too short for ACCOUNT (9+) but are exactly the
      // shape of a CIF, folio, customer ID, employee ID or OTP.
      kind: 'SHORT_ID',
      re: /\b\d{6,8}\b/g,
    },
  ];

  // SHORT_ID also hits prices and years, so the balanced profile drops it.
  function rulesFor(profileName) {
    if (profileName === 'balanced') {
      return GROUPED_RULES.filter((r) => r.kind !== 'SHORT_ID');
    }
    return GROUPED_RULES;
  }

  // Re-OCR the exact outgoing PNG and assert no PII span survives.

  // Tokens we deliberately PRINT onto redaction bars, and Set-of-Mark chip
  // numbers, are expected in the egress frame and are not leaks.
  const EXPECTED_ARTIFACT_RE = /^<PII:[A-Z]+#\d+>$|^\d{1,3}$/;

  async function verifyEgress(egressBlob, deps) {
    const t0 = performance.now();
    try {
      const data = await deps.ocrRecognize(egressBlob);
      const words = deps.flattenWords(data)
        .filter((w) => w.text && w.text.trim() && w.bbox);
      const { text } = deps.buildTextIndex(words);
      const spans = deps.detectPiiSpans(text, deps.kinds);

      const leaks = spans
        .filter((s) => !EXPECTED_ARTIFACT_RE.test(s.raw.trim()))
        .map((s) => ({ kind: s.kind, length: s.raw.length }));

      return {
        ok: leaks.length === 0,
        scanned: words.length,
        leaks,
        ms: Math.round(performance.now() - t0),
      };
    } catch (e) {
      // A verification that could not run is NOT a pass. Fail closed: the
      // caller must treat this as unverified and refuse to claim otherwise.
      return {
        ok: false,
        scanned: 0,
        leaks: [],
        skipped: e.message,
        ms: Math.round(performance.now() - t0),
      };
    }
  }

  root.AAVARAN_PII = {
    GROUPED_RULES,
    rulesFor,
    verifyEgress,
    EXPECTED_ARTIFACT_RE,
  };
}(self));
