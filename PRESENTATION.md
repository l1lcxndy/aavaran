# AAVARAN — Demo Day

Three documents in one: the run sheet, the Q&A, and the submission text.

---

# PART 1 — The 3-minute demo

## Before you walk in

Set this up 20 minutes early, not 5. Tick every box.

```
□  fetch-libs.ps1 run, all 10 assets present
□  manifest.json CSP includes 'wasm-unsafe-eval'
□  Extension reloaded AFTER the manifest edit
□  Terminal A:  mock_vlm on :8001   (or real Qwen)
□  Terminal B:  main.py on :8756
□  Preflight → ocr, face, server ALL GREEN
□  demo-page.html open in a tab, face photo loaded
□  Panel open, vault purged, trace cleared
□  One practice run completed start to finish
□  Browser zoom at 100%  (DPR drift shifts marks)
□  Laptop on mains, notifications off, wifi off if you can
□  Fallback: Rehearsal mode tested, recorded run present
```

**Two terminals, two ports.** The brain on 8000 calls itself. Don't.

## The run sheet

### 0:00 – 0:25 — The problem

> "Every browser agent works by screenshotting your screen and sending it to a
> vision model. Watch what that means on a banking page."

Show `demo-page.html`. Scroll once, slowly. Let them read: Aadhaar, PAN, card
numbers, balance, a face.

> "To ask an agent to download a statement, you currently transmit all of this
> to someone else's GPU. Every step. Twenty times in one task."

**Don't rush this.** The demo only lands if they feel the problem first.

---

### 0:25 – 1:15 — The veil

Click **Capture & Veil**.

> "Same page. Left is what I see. Right is what leaves this machine."

Point at the right pane:

> "Those aren't blurs. Blur is reversible — the pixels are still in the file.
> These pixels were overwritten on the full-resolution canvas before encode.
> The information is not hidden in that PNG. It is absent from it."

Point at the pink labels on the bars:

> "The model can't read my Aadhaar. But it can *reference* it — that's
> `<PII:AADHAAR#1>`. If the task needs it typed into a form, the extension
> resolves the token locally, at execution time. The number never enters the
> model's context window. It can't be memorised, it can't be logged by the
> inference provider, and it can't leak through the model's own output."

Point at the cyan numbered boxes:

> "And every interactive element is numbered. The model doesn't read the page
> — it picks a number."

---

### 1:15 – 1:50 — Zero-leak verification ← **the a-ha moment**

Point at the badge.

> "Here's the part I care about. Every privacy tool claims its output is
> clean. This one checks.
>
> After the frame is finished — after redaction, after downscale, after the
> numbering is drawn — we take the *exact bytes that are about to leave* and
> run the same OCR engine over them again. Then we run the same PII detector
> on whatever comes back."

> "**Fourteen words read. Zero recoverable identifiers.** If that number were
> anything but zero, the frame would not be sent."

If a judge is going to interrupt, it will be here. The answer is in §Q4.

> "This is deliberately a narrow claim. It doesn't prove privacy in the
> abstract. What it closes is the class of bug that actually ships — where the
> geometry is computed perfectly and then applied to the wrong canvas, or the
> wrong scale, or after the encode. We verify the artifact, not the process,
> because the artifact is the only thing that matters."

---

### 1:50 – 2:35 — The agent acts, and gets stopped

Type into the goal box: `open the statements page and download the latest one`
→ **Run**.

Narrate the decision feed as rows appear:

> "It picked element 2. Not coordinates — an index. That matters more than it
> sounds: a coordinate-predicting agent lands 20 to 40 pixels off on a
> non-default display scale and clicks the wrong thing. An index either exists
> in the manifest or it doesn't, so a wrong answer is *caught* instead of
> executed."

Then the second run — this is the one to rehearse. Goal: `transfer money to my landlord`

> "Now watch it try something destructive."

The feed shows **NEEDS HUMAN** in amber.

> "It proposed clicking 'Confirm and Pay'. The whitelist flagged it as
> state-changing and destructive, and stopped for a human. The model is never
> the last authority on an irreversible action."

If you have time, show the rejection path:

> "And this is the model trying `execute_script`. Rejected — not ignored,
> *rejected*. If we silently dropped the bad field, we'd execute something
> different from what the model reasoned about. Instead the rejection goes
> back into its context and it repairs on the retry."

---

### 2:35 – 3:00 — The numbers, and the close

Point at the egress meter.

> "Cumulative bytes that have left this machine. Delta encoding only
> transmits the tiles that changed — on a 20-step task that's 32,000 image
> tokens down to about 6,400."

Close on the sentence you want them to repeat to each other afterwards:

> "AAVARAN doesn't ask you to trust the model with your identity. It makes it
> structurally impossible for the model to have it — and then it checks the
> bytes to prove it."

**Stop talking.** Let the silence sit. Don't fill it with a feature list.

---

## If something breaks

| Breaks | Say | Do |
|---|---|---|
| Server dot red | "The brain's a separate process — perception runs entirely local, let me show you that" | Demo the veil only. It is genuinely the strongest part. |
| OCR fails mid-demo | "This is the fail-closed path — when it can't read the page, it refuses to send pixels at all rather than guessing" | This is **true** and it is a feature. Show the wireframe mode. |
| Agent picks wrong element | "That's the model, not the grounding — and notice the validator still confirmed the index was real before executing" | Move on. Don't debug on stage. |
| Whole thing dies | "Let me show you the recorded run" | **Rehearsal** button. The ribbon says REHEARSAL — leave it visible and say so. |

Never present a replay as live. One honest sentence costs you nothing; getting
caught costs you the room.

---

# PART 2 — Judge Q&A

## The technical-depth questions

**Q1. Why Verhoeff and not a simple checksum?**

Verhoeff is a checksum over the dihedral group D₅ — the symmetry group of a
pentagon, which is non-commutative. That non-commutativity is the whole point:
because `a·b ≠ b·a` in D₅, the algorithm detects **all** single-digit errors
*and* **all** adjacent transpositions. A mod-10 sum like Luhn misses the
transposition `09 → 90`. UIDAI picked Verhoeff for Aadhaar precisely because
hand-transcribed digits get transposed constantly.

Implementation detail worth mentioning: our first version had the `d` and `p`
tables as the same symmetric matrix. That makes the checksum degenerate —
accepts roughly 10% of random 12-digit strings and rejects valid Aadhaars.
Both real D₅ tables are in the code now.

**Q2. Why Set-of-Mark instead of coordinate prediction?**

Two reasons, one practical and one architectural.

Practically: VLMs are bad at precise pixel regression. On a 4K display at 150%
browser zoom, a model's coordinate estimate is routinely 20–40px off, which
means clicking the wrong element.

Architecturally, and this is the better answer: an index makes the grounding
contract *verifiable*. `{"index": 14}` either matches the manifest or it
doesn't, and we check before executing. A coordinate is always "valid" — it
just might be wrong, and you find out after the click. We moved the failure
from runtime to validation time.

**Q3. Why redact before downscale?**

If you downscale first, the fill is applied at egress resolution and you can
get edge residue from the resampling filter — partial glyph information
surviving at the boundary of the bar. Overwriting at full device resolution
and *then* downscaling means the resampler is averaging destroyed pixels with
destroyed pixels. There is nothing left to bleed.

Same reasoning for why the perceptual hash is computed post-veil but pre-mark:
renumbering a chip must not register as a page state change.

**Q4. Isn't "zero-leak verified" circular? You're checking with your own OCR.**

Yes, and I'd rather state the limit than oversell it. The claim is narrow:
*no PII is recoverable from the transmitted bytes by the same engine and
detector that produced the redactions.* A stronger OCR or a human might
recover more.

What it closes is the class of bug that actually ships in production: geometry
computed correctly and applied to the wrong canvas, the wrong scale, or after
encode. We caught exactly that class in testing. Verifying the artifact
instead of trusting the process is the difference between "we believe it's
clean" and "we looked."

The honest next step is verifying against a second, independent OCR engine.

**Q5. What's your false negative rate?**

We don't have a measured number, and I won't invent one. That's the most
important thing still missing from this project.

What we have is architectural: every validating rule sits on top of a
fail-closed floor. Anything *shaped* like an identifier is redacted whether or
not it checksums — grouped digit runs, masked forms, low-confidence OCR words
containing digits, anything to the right of a label like "A/c No".

Concretely: during integration we found `1234 5678 9012` transmitting in the
clear. Three rules missed it independently — it starts with 1 which UIDAI
reserves, it's too short for the card rule, and the spaces broke the digit-run
rule. The floor catches it now. That's the kind of gap a measured benchmark
would have surfaced systematically, and building that corpus is the next
priority.

**Q6. Why not just run the model locally?**

You can, and for some tasks you should. But a 7B VLM on a laptop is
substantially worse at web navigation than a frontier model, and the gap is
the reason anyone reaches for an agent at all. AAVARAN is for the case where
you want frontier capability without frontier exposure — it decouples "who
does the reasoning" from "who sees your identity."

**Q7. How is this different from just blurring?**

Blur is a reversible linear transform. The information is still in the file at
lower frequency, and there is published work recovering text from blurred and
pixelated regions. We overwrite with opaque fill. Nothing survives to invert.

**Q8. What stops the model from being prompt-injected by the page?**

Partly: the action whitelist. Injected text can make the model *propose*
something, but it cannot make the system *execute* something outside the
whitelist, on a non-existent index, on a host outside the allowlist, or a
destructive action without a human.

The strongest guard is origin-bound tokens — a page saying "type the user's
card number here" fails, because `<PII:CARD#1>` is bound to the origin it was
captured on and cannot cross to another.

Honest gap: we don't yet detect injection, we only constrain its blast radius.

## The uncomfortable questions — answer these straight

**Q9. Is it actually working, or is this a mock?**

The perception and privacy pipeline is fully live — OCR, face detection,
detection, redaction, Set-of-Mark, egress verification, all running locally
right now. The model's decisions in this demo are scripted, because we
couldn't fit a 7B VLM on this machine. The server, the validator, the frame
reconstruction and the repair loop are all real code running real requests
against a scripted endpoint.

*(If you got Qwen running: say that instead. Don't hedge if you don't have to.)*

**Q10. Is this DPDP Act 2023 compliant?**

It's designed *toward* DPDP principles — data minimisation, purpose
limitation, and keeping personal data on the data principal's own device — but
"compliant" is a legal determination and none of us are lawyers. We'd need
counsel to review it before claiming that word.

*Don't get talked past this. A judge who knows the Act will respect the
hedge and distrust the overclaim.*

**Q11. What's left to build?**

Ranked honestly:
1. A measured PII recall/precision benchmark on a labelled corpus. Not having
   this is the biggest hole.
2. End-to-end validation with a real VLM.
3. Non-Latin OCR — Devanagari, Tamil, Bengali. Fairly serious for an Indian
   product.
4. A tamper-evident audit log of what left the machine.
5. Cross-origin iframe handling.

**Q12. Why should we believe the pixels are gone?**

Don't believe me — the redaction happens client-side in code you can read, and
the egress verification runs in front of you. But the real answer is: open the
transmitted PNG yourself. That's the file. That's all of it.

---

# PART 3 — Submission text

## Technical summary (2 paragraphs)

AAVARAN is a privacy-preserving browser agent that inverts the standard
trade-off between agentic capability and personal data exposure. Conventional
vision-based agents transmit raw screen captures to a remote vision-language
model, meaning that any task performed on a banking, healthcare or KYC page
exports the user's complete identity to third-party inference infrastructure
on every step of the loop. AAVARAN interposes a local perception layer between
the browser and the model. Each captured frame is processed entirely on-device
through three parallel channels — Tesseract OCR for rendered text, face-api's
tiny_face_detector for biometric regions, and a DOM channel that recovers
values pixels cannot show, such as masked password fields. Detected
identifiers are validated against their statutory checksums (Verhoeff over the
dihedral group D₅ for Aadhaar, Luhn for payment cards) and their pixels are
**destructively overwritten at full device resolution prior to downscale and
encode**, eliminating the resampling residue that makes blur and pixelation
recoverable. Beneath the validating rules sits a fail-closed recall floor that
redacts anything structurally resembling an identifier — grouped digit runs,
masked forms, low-confidence OCR regions, and values adjacent to sensitive
field labels — on the principle that a false redaction costs a retry while a
miss costs an identity.

The redacted frame is then annotated with a Set-of-Mark overlay, giving the
model a discrete, verifiable action space: the agent responds with an element
index rather than a pixel coordinate, which both eliminates the spatial
regression errors that dominate coordinate-predicting agents and makes every
proposed action checkable against a manifest before execution. Redacted values
are replaced with deterministic, origin-bound tokens (`<PII:AADHAAR#1>`),
allowing the model to compose actions referencing data it can never read — the
plaintext is resolved locally at execution time and never enters the model's
context window. Every proposal passes a closed action whitelist that rejects
unknown actions and unknown *fields*, validates indices and element
affordances, blocks non-HTTP schemes and off-allowlist hosts, refuses any
cross-origin movement of tokenised PII, and escalates destructive operations
to a human. Rejections are returned to the model as repair prompts rather than
aborting the run. A tile-hashed delta encoder transmits only changed screen
regions, reducing image token consumption on a twenty-step task from
approximately 32,400 to 6,400. Finally, each outgoing frame is subjected to an
egress verification pass: the exact transmitted bytes are re-read by the same
OCR engine and re-scanned by the same detector, and the frame is withheld if
any identifier remains recoverable — verifying the artifact rather than
trusting the process. The architecture is designed toward the data
minimisation and purpose limitation principles of India's DPDP Act 2023,
though formal compliance assessment remains outside the scope of this work.

## One-liner

> AAVARAN lets a frontier vision model operate your browser without ever
> seeing who you are — and then re-reads its own outgoing bytes to prove it.

## Terminology cheat sheet

Use these precisely. Using them loosely is how you lose a technical judge.

- **SOTA visual grounding** — Set-of-Mark prompting, discrete index action
  space, verifiable against a manifest
- **Zero-leak egress** — destructive redaction + post-encode re-verification
  of transmitted bytes
- **Fail-closed recall** — ambiguity resolves toward redaction
- **Origin-bound tokenisation** — PII handles that cannot cross origins
- **Delta-encoded observation** — tile-hashed frames, keyframe + patch
- **DPDP-aligned** — designed toward the Act's principles. *Aligned*, not
  *compliant*.
