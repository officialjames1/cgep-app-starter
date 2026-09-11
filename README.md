# cgep-app-starter

> Patient Intake API for "Acme Health". The deliberately-flawed workload your **CGE-P capstone** wraps with GRC controls.

## What this is

A minimal AWS workload: VPC, Lambda, API Gateway, DynamoDB, S3. It ingests patient intake submissions over HTTPS. Think of it as a system you have just inherited from an engineering team and been asked to make audit-defensible.

This repository ships **non-compliant on purpose**. Your job in the capstone is not to rewrite this app. Your job is to wrap it with the four CGE-P layers (Terraform GRC baseline, Rego policies, GitHub Actions evidence pipeline, OSCAL component) so the same workload becomes audit-defensible against HIPAA, SOC 2, and CMMC L2.

## The deploy gate

If you cannot deploy this starter, you cannot pass the capstone. Real GRC engineers inherit working systems. Step zero is making the system run.

```bash
git clone https://github.com/GRCEngClub/cgep-app-starter
cd cgep-app-starter

# Confirm you're authenticated to the right account:
make creds AWS_PROFILE=<your-sandbox-profile>

make deploy AWS_PROFILE=<your-sandbox-profile>
make test    AWS_PROFILE=<your-sandbox-profile>
```

> **AWS SSO note:** if your profile is SSO-based, Terraform's AWS provider can fail to read it directly with `failed to find SSO session section`. The Makefile's `eval $(aws configure export-credentials)` pattern handles this. If you're running `terraform` commands by hand, do the same export first.

Expected output of `make test`:

```json
{
    "submission_id": "f1e3...",
    "status": "received"
}
```

When you're done exploring: `make destroy`.

## What you build on top

Fork the repo into your own `cgep-capstone` and add:

1. **Layer 1 — GRC baseline (Terraform).** KMS keys, an S3 evidence vault with Object Lock, a CloudTrail trail. Bring this starter's data stores under your CMK.
2. **Layer 2 — OPA policy suite (Rego).** Five or more policies that catch the named gaps in [GAPS.md](GAPS.md). Each policy maps to at least one control from the framework you choose.
3. **Layer 3 — GitHub Actions pipeline.** Plan → Conftest gate → apply → Cosign sign → upload to vault.
4. **Layer 4 — OSCAL component.** A `component-definition.json` describing how your governed system implements its controls.

Full brief: `docs/labs/07_01_capstone_brief.md` in the course content repo.

## Framework mapping is required

Your capstone must declare a primary framework: **HIPAA Security Rule**, **SOC 2 Trust Services Criteria**, or **CMMC Level 2**. Every policy carries at least one control ID from your chosen framework. Your OSCAL component's `control-implementations` reference your framework's catalog.

A starter mapping is in [FRAMEWORKS.md](FRAMEWORKS.md). It is not the only valid mapping. You're expected to defend yours.

## Cost

Roughly $0 if destroyed within an hour. Lambda + API Gateway + DynamoDB + S3 are all pay-per-use, and an empty deployment generates no traffic. CloudTrail (which you add) costs cents.

## Layout

```
cgep-app-starter/
├── README.md            # this file
├── WORKLOAD.md          # what the API does
├── GAPS.md              # the named flaws your policies must catch
├── FRAMEWORKS.md        # HIPAA / SOC 2 / CMMC mapping primer
├── Makefile             # make deploy | test | destroy
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── lambda/handler.py
└── test/
    └── intake.sh
```

## License

MIT. Fork freely. Submissions remain learners' own work.

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
