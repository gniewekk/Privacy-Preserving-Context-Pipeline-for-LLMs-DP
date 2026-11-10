# ADR-009: Extract-Then-Anonymize PDF Processing (Fail-Closed on Raw Binaries)

- **Status:** Accepted
- **Date:** 2026-11-10
- **Component:** `src/pipeline/` (`DocumentExtractorFilter`, `InboundPipeline`)

---

## 1. Context & Problem

Enterprise and clinical users frequently attach PDF documents (invoices, discharge summaries, contracts) to LLM prompts. Forwarding raw binary PDF files directly to external multimodal LLM APIs introduces three severe data leakage vectors:
1. **Hidden Document Metadata (XMP / Info Dictionary):** Author names, employee usernames, organization identifiers, and edit histories embedded in PDF headers.
2. **Unredacted Object Layers:** Text visually covered by black rectangles in poorly redacted PDFs remains readable in the underlying PDF object tree.
3. **Embedded Images & Scanned Pages:** Multimodal vision LLMs can read PII/PHI directly from pixel data in scanned documents, signatures, or medical stamps bypassing text-only detectors.

---

## 2. Decision

We enforce an **Extract-Then-Anonymize, Fail-Closed on Raw Binaries** policy via `DocumentExtractorFilter` at the entry of the inbound pipeline:

1. **Zero Raw Binary Egress:** Raw PDF binaries and attachment byte streams are never forwarded to any external `LLMDispatcher`.
2. **Metadata Stripping & Plaintext Extraction:** `DocumentExtractorFilter` parses the document locally, discards all XMP/Info dictionary metadata, extracts only the textual content layer, and writes the normalized text into `PipelineContext` for standard `DetectionFilter` -> `AnonymizationFilter` processing.
3. **Fail-Closed Policy on Scanned PDFs / Embedded Images:**
   - If a PDF lacks a text layer (i.e., a scanned image) or contains embedded raster images while no trusted local OCR engine is configured (`STRICT_NO_OCR` mode), the filter immediately aborts execution by raising a fail-closed domain exception (`UnsupportedMediaWithPotentialPIIError`) and records an immutable `AuditEvent`.
   - Only when a local, network-isolated OCR adapter is explicitly injected (`LOCAL_OCR_ENABLED`) is raster text extracted and routed through the PII detection chain.

---

## 3. Rejected Alternatives

### Alternative A: Forwarding Raw PDFs to Multimodal Vision LLMs with Prompt Instructions to "Ignore PII"
Relying on system prompts to tell the external LLM not to repeat sensitive data found in the PDF.
- **Why Rejected:** Completely violates Privacy by Design and GDPR Art. 25/44. Once the raw binary reaches the external provider, PII/PHI and metadata have already leaked across the trust boundary.

### Alternative B: Silently Ignoring Embedded Images and Extracting Only Available Text
Extracting whatever text exists in a hybrid PDF while silently dropping image warnings.
- **Why Rejected:** Risks incomplete context or false confidence when sensitive caveats or identifiers appear only on scanned attachments. Explicit fail-closed rejection (or local OCR) makes the security boundary deterministic and auditable.

---

## 4. Trade-offs & Consequences

### Positive
- **Eliminates Metadata & Hidden-Layer Leaks:** Only sanitized plaintext leaves the pipeline; XMP metadata and binary structures are destroyed at the boundary.
- **Seamless Filter Composition:** Because `DocumentExtractorFilter` implements the standard `Filter` interface (`process(context: PipelineContext) -> PipelineContext`), downstream detectors and strategies operate identically on extracted PDF text and standard string prompts.

### Negative / Mitigations
- **Loss of Complex Visual Layout:** Converting PDFs to normalized text/Markdown strips visual styling and complex multi-column positioning. *Mitigation:* Preserving structural Markdown tables during extraction retains semantic layout needed for LLM reasoning without exposing binary hazards.

---

## 5. Compliance with Scenarios

- **Scenario 1 & 3 (Pseudonymization & EU Data Residency for PHI):** Ensures clinical PDF attachments are stripped of metadata, scanned for PHI, and gated by `ResidencyGate` before any external dispatch.
- **Week 6 Extensibility:** Demonstrates how new input modalities (PDFs, structured documents) can be normalized via an entry `Filter` without changing downstream `PIIDetector` or `AnonymizationStrategy` implementations.
