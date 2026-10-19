'use strict';
/* ==========================================================================
 * AAVARAN — pii.hardening.js
 * ==========================================================================
 * Load in offscreen.html AFTER offscreen.hardening.js, BEFORE offscreen.js.
 *
 * Two things live here:
 *   A. GROUPED_RULES — the recall gap that let a real Aadhaar through.
 *   B. verifyEgress() — the Zero-Leak check. Re-OCRs the exact bytes about to
 *      leave the machine and asserts nothing readable survives.
 * ========================================================================== */

(function (root) {
  /* ======================================================================
   * A. The grouped-digit gap
   * ======================================================================
   * Observed failure: "Aadhaar: 1234 5678 9012" rendered on screen was
   * transmitted in full.
   *
   *   AADHAAR rule  /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/  -> no match,
   *                 first digit is 1 (UIDAI reserves 0 and 1)
   *   CARD rule     needs 13-19 digits                      -> no match at 12
   *   ACCOUNT rule  /\b\d{9,18}\b/                          -> no match, the
   *                 spaces split it into three 4-digit runs
   *
   * Every rule in the set is a *validating* rule. That is correct for
   * precision and wrong for a redaction path, where recall is the objective:
   * a false redaction costs one retry, a miss costs an identity. Anything
   * SHAPED like an identifier is redacted whether or not it checksums.
   *
   * Insert these AFTER the validating rules in RULES[] so a genuine Aadhaar
   * still claims its span first and still gets its proper AADHAAR token.
   * ====================================================================== */

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

  /**
   * Splice into the existing RULES array. Placement matters: after the
   * validating rules (so AADHAAR/CARD/PAN claim their spans first), before
   * nothing (these are the floor).
   *
   * In offscreen.js, immediately after the RULES const:
   *   RULES.push(...AAVARAN_PII.GROUPED_RULES);
   *
   * SHORT_ID is aggressive by design and will redact prices, years in tables,
   * and order numbers. That is the intended trade on a strict/paranoid
   * profile. Gate it if you are on `balanced`:
   *   RULES.push(...AAVARAN_PII.rulesFor(profile.name));
   */
  function rulesFor(profileName) {
    if (profileName === 'balanced') {
      return GROUPED_RULES.filter((r) => r.kind !== 'SHORT_ID');
    }
    return GROUPED_RULES;
  }

  /* ======================================================================
   * B. Zero-Leak egress verification
   * ======================================================================
   * Every privacy pipeline claims its output is clean. This one checks.
   *
   * The claim being tested is deliberately narrow and therefore defensible:
   *
   *   "No PII is recoverable from the bytes that leave this machine, by the
   *    same OCR engine and the same detector that produced the redactions."
   *
   * It is NOT a proof of absolute privacy — a stronger OCR, a human, or a
   * different detector might still recover something. But it closes the
   * entire class of bug where the redaction geometry is computed correctly
   * and then applied to the wrong canvas, at the wrong scale, or after the
   * encode. Those are the bugs that actually ship.
   *
   * This runs on the FINAL PNG, post-downscale, post-Set-of-Mark. Verifying
   * the artifact rather than the process is the whole point: it does not
   * matter what the pipeline intended, only what is in the bytes.
   * ====================================================================== */

  // Tokens we deliberately PRINT onto redaction bars, and Set-of-Mark chip
  // numbers, are expected in the egress frame and are not leaks.
  const EXPECTED_ARTIFACT_RE = /^<PII:[A-Z]+#\d+>$|^\d{1,3}$/;

  /**
   * @param {Blob} egressBlob  the exact PNG that will be transmitted
   * @param {object} deps      { ocrRecognize, flattenWords, buildTextIndex,
   *                             detectPiiSpans, kinds }
   * @returns {Promise<{ok:boolean, scanned:number, leaks:object[], ms:number, skipped?:string}>}
   */
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

  /**
   * Wire at the very end of veil(), after the egress PNG exists:
   *
   *   let verification = { ok: false, skipped: 'disabled' };
   *   if (cfg.verifyEgress !== false) {
   *     verification = await AAVARAN_PII.verifyEgress(egressBlob, {
   *       ocrRecognize, flattenWords, buildTextIndex, detectPiiSpans,
   *       kinds: cfg.kinds,
   *     });
   *     if (!verification.ok && cfg.blockOnLeak) {
   *       throw new Error(`egress blocked: ${verification.leaks.length} PII
   *         span(s) still readable in the outgoing frame`);
   *     }
   *   }
   *   // ...include `verification` in the returned payload
   *
   * Cost is one extra OCR pass (~400-900ms at egress resolution, which is far
   * smaller than the OCR resolution, so it is cheaper than the first pass).
   * Turn it off for throughput runs, leave it on for the demo — it is the
   * single most convincing thing on the screen.
   */

  root.AAVARAN_PII = {
    GROUPED_RULES,
    rulesFor,
    verifyEgress,
    EXPECTED_ARTIFACT_RE,
  };
}(self));
