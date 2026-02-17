# Registry Proxy Bug Notes

## 2026-02-17 - Digest alias confirm can fail with 422

- Symptom:
  - BuildKit export fails at manifest finalize with:
    - `digest alias confirm failed`
    - backend `422 Validation failed`
- Context:
  - Main OCI ref/tag save+confirm succeeds.
  - Follow-up digest alias (`oci_digest_<manifest_digest>`) confirm may fail.
- Mitigation implemented in CLI:
  - Keep primary manifest save/confirm strict.
  - Make digest-alias save/confirm best-effort (warn on failure, do not fail export).
  - Include alias tag in alias confirm request.
- Why:
  - Digest alias improves digest-addressed lookup, but should not block cache export success.
  - OCI cache export correctness depends on the primary ref manifest write.
