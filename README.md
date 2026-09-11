
---

## For graders: how to verify this capstone

This section covers what you can verify directly against this repository (no AWS access needed) versus what's evidenced by CI logs (since this deploys to the author's personal AWS sandbox, not a shared account).

### Fully self-contained checks — run these yourself

```bash
git clone https://github.com/officialjames1/cgep-app-starter
cd cgep-app-starter

# 1. Policy suite: 8 GAP policies + 3 inherited lab policies, all with passing/failing tests
opa test ./policies -v
# Expect: 31/31 tests passing

# 2. Terraform syntax and internal consistency (no AWS credentials required)
cd terraform
terraform init -backend=false
terraform validate
# Expect: "Success! The configuration is valid."
cd ..

# 3. OSCAL schema validation
trestle validate -a
# Expect: VALID for both component-definition.json and profile.json
```

### CI/CD pipeline — verifiable via GitHub Actions logs

Live re-running of `terraform plan`/`apply` requires the author's AWS credentials and isn't reproducible by a third party. Instead, verify via the Actions tab:

- **Actions tab:** https://github.com/officialjames1/cgep-app-starter/actions
- **The merged (green) PR:** demonstrates `plan-and-gate` passing all 9 enforced policy namespaces on a real `terraform plan` against live infrastructure, followed by a real `terraform apply`, Cosign signing, and evidence upload in the subsequent `apply-and-sign` job.
- **The closed (red) PR** (`TEST: deliberately broken PR (GAP-07 regression)`): demonstrates the gate correctly blocking a real, reintroduced wildcard-IAM violation, with the exact failing policy messages visible in the job log.
- **Signed evidence bundle:** every successful `apply-and-sign` run uploads the actual signed bundle (`.tar.gz`, `.sha256`, `.sig.bundle`) as a downloadable GitHub Actions artifact named `signed-evidence-bundle-<run-id>`. You can download this directly and independently verify it:

```bash
# After downloading the three files from a run's artifacts:
cosign verify-blob \
  --bundle evidence-<run-id>-<sha>.tar.gz.sig.bundle \
  --certificate-identity-regexp "^https://github.com/officialjames1/cgep-app-starter/\.github/workflows/grc-gate\.yml@.*$" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  evidence-<run-id>-<sha>.tar.gz

sha256sum evidence-<run-id>-<sha>.tar.gz
# Compare against the .sha256 file in the same artifact
```

Both commands succeeding with no error confirms the bundle is authentic (signed by this exact repo's workflow, not forged) and unmodified since signing — independent of any claim in this write-up.

### Documents to read

- **`GAPS.md`** — the eight named flaws this capstone remediates.
- **`WRITEUP.md`** — framework justification (CMMC Level 2 / NIST SP 800-171 Rev 3), control coverage table, design decisions, a full evidence-chain trace against a real run, and an honest account of what was and wasn't closed (GAP-05, GAP-06, and the WAF portion of GAP-08 are documented as accepted risk, not silently dropped).
- **`oscal/components/your-component.json`** — real control-to-resource mappings with links to signed evidence for every closed control.
