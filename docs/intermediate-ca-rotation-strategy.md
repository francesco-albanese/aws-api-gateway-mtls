# Intermediate CA Key Rotation Strategy

## Executive Summary

This document outlines the strategy for rotating the Intermediate CA in case of key compromise. The goal is a **one-click pipeline execution** that:
1. Generates a new Intermediate CA (signed by existing Root CA)
2. Updates the S3 truststore
3. Re-provisions all client certificates
4. Maintains API availability with minimal disruption

---

## Threat Model

**Scenario:** The Intermediate CA private key has been compromised.

**Impact:**
- Attacker can issue valid client certificates
- All existing client certificates remain valid but should be considered untrusted
- Root CA is NOT compromised (can sign a new Intermediate)

**Required Actions:**
1. Revoke/invalidate the old Intermediate CA
2. Generate new Intermediate CA
3. Re-issue all client certificates
4. Update truststore to only trust the new chain

---

## Rotation Strategy Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    ONE-CLICK ROTATION PIPELINE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1: PREPARE                                               │
│  ├── Fetch Root CA from SSM (private key + cert)                │
│  ├── Generate new Intermediate CA (signed by Root)              │
│  └── Create new truststore bundle                               │
│                                                                 │
│  Phase 2: DEPLOY TRUSTSTORE                                     │
│  ├── Upload new truststore to S3 (versioned)                    │
│  ├── Update Intermediate CA in SSM Parameter Store              │
│  └── API Gateway picks up new truststore automatically          │
│                                                                 │
│  Phase 3: RE-PROVISION CLIENTS                                  │
│  ├── Read client list from clients/{env}.json                   │
│  ├── Revoke old certs in DynamoDB (status: revoked)             │
│  ├── Generate new client certs (signed by NEW Intermediate)     │
│  └── Store new certs in SSM + update DynamoDB metadata          │
│                                                                 │
│  Phase 4: VERIFY & CLEANUP                                      │
│  ├── Validate mTLS connectivity with new certs                  │
│  ├── Archive old Intermediate CA (for audit)                    │
│  └── Notify stakeholders                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Detailed Phase Breakdown

### Phase 1: Prepare New Intermediate CA

**Objective:** Generate a new Intermediate CA without touching the Root CA storage.

**Implementation Approach:**

```
New Script: ca_operations/scripts/rotate_intermediate.py
```

**Steps:**
1. Fetch Root CA private key from SSM: `/{project}/{account}/ca/root/private-key`
2. Fetch Root CA certificate from SSM: `/{project}/{account}/ca/root/certificate`
3. Generate new RSA 4096-bit key pair for Intermediate CA
4. Create CSR with same subject as before (or updated serial)
5. Sign with Root CA (5-year validity)
6. Add constraints: `pathlen:0`, `CA:TRUE`, Key Usage: `keyCertSign, cRLSign`
7. Output to local filesystem for Terraform

**Key Considerations:**
- New Intermediate CA gets a **new serial number** (UUID-based)
- Subject Distinguished Name can include rotation timestamp for identification
- Keep same organizational info for consistency

---

### Phase 2: Deploy New Truststore

**Objective:** Update S3 truststore so API Gateway only accepts the new chain.

**Truststore Content Strategy:**

| Option | Truststore Contents | Effect |
|--------|---------------------|--------|
| **A. Hard Cutover** | New Intermediate + Root | Old client certs immediately rejected |
| **B. Grace Period** | Old + New Intermediate + Root | Both old and new certs work temporarily |
| **C. Recommended** | New Intermediate + Root | Hard cutover (compromise = no grace) |

**Recommendation:** Option A (Hard Cutover)

In a compromise scenario, we cannot allow a grace period since the attacker could still issue certificates signed by the compromised Intermediate.

**Terraform Changes:**
- Update `certificate-bootstrap/ssm-ca-parameters.tf` to read new Intermediate
- S3 object versioning captures the old truststore for audit
- API Gateway automatically picks up new truststore (no restart needed)

---

### Phase 3: Re-Provision All Client Certificates

**Objective:** Issue new certificates for all clients, signed by the new Intermediate CA.

**Client Discovery:**
- Read from `clients/{environment}.json`
- Query DynamoDB for all active `serialNumber` entries

**Per-Client Actions:**
1. Mark existing cert in DynamoDB as `status: revoked`
2. Generate new client certificate (RSA 4096, 395-day validity)
3. Sign with NEW Intermediate CA
4. Update SSM Parameter Store:
   - `/{project}/{account}/clients/{client_id}/private-key` → new key
   - `/{project}/{account}/clients/{client_id}/certificate` → new cert
5. Insert new metadata in DynamoDB (new serial number)

**Rollback Consideration:**
- Old certificates are marked `revoked`, not deleted
- DynamoDB retains history for audit
- SSM Parameter Store versions can be rolled back if needed (but shouldn't be in compromise)

---

### Phase 4: Verification & Notification

**Automated Verification:**
```bash
# Test mTLS connectivity with a new client cert
curl --cert new-client.pem --key new-client.key \
     https://api.example.com/health
```

**Post-Rotation Checklist:**
- [ ] API Gateway returns 200 with new certs
- [ ] API Gateway returns 403 with old certs
- [ ] All clients in DynamoDB have new serial numbers
- [ ] Old Intermediate marked as revoked in audit log
- [ ] CloudWatch Logs show successful mTLS handshakes

**Notification:**
- Slack/Email to security team
- Update incident response ticket
- Distribute new client certificates to API consumers

---

## Pipeline Implementation

### GitHub Actions Workflow

**New Workflow:** `.github/workflows/rotate-intermediate-ca.yml`

```yaml
name: Rotate Intermediate CA (Emergency)

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Target environment'
        required: true
        type: choice
        options: [sandbox, staging, uat, production]
      confirm_rotation:
        description: 'Type ROTATE to confirm'
        required: true
        type: string

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - name: Confirm rotation intent
        run: |
          if [ "${{ inputs.confirm_rotation }}" != "ROTATE" ]; then
            echo "Confirmation failed. Type ROTATE to proceed."
            exit 1
          fi

  rotate:
    needs: validate
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: eu-west-2

      - name: Generate new Intermediate CA
        run: |
          make ca-rotate-intermediate ACCOUNT=${{ inputs.environment }}

      - name: Deploy new truststore
        run: |
          make tf-apply STACK=certificate-bootstrap ACCOUNT=${{ inputs.environment }}

      - name: Re-provision all clients
        run: |
          make ca-reprovision-all-clients ACCOUNT=${{ inputs.environment }}

      - name: Deploy client provisioning
        run: |
          make tf-apply STACK=client-provisioning ACCOUNT=${{ inputs.environment }}

      - name: Verify mTLS connectivity
        run: |
          make verify-mtls ACCOUNT=${{ inputs.environment }}

      - name: Cleanup local artifacts
        if: always()
        run: |
          make ca-clean ACCOUNT=${{ inputs.environment }}
```

### Makefile Targets

**New targets in `makefiles/ca.mk`:**

```makefile
# Rotate Intermediate CA (fetches Root from SSM, generates new Intermediate)
ca-rotate-intermediate:
	@echo "Rotating Intermediate CA for $(ACCOUNT)..."
	python ca_operations/scripts/rotate_intermediate.py \
		--project-name $(PROJECT_NAME) \
		--account-name $(ACCOUNT)

# Re-provision all client certificates
ca-reprovision-all-clients:
	@echo "Re-provisioning all clients for $(ACCOUNT)..."
	python ca_operations/scripts/reprovision_all_clients.py \
		--project-name $(PROJECT_NAME) \
		--account-name $(ACCOUNT) \
		--clients-file clients/$(ACCOUNT).json

# Verify mTLS after rotation
verify-mtls:
	@echo "Verifying mTLS connectivity for $(ACCOUNT)..."
	python ca_operations/scripts/verify_mtls.py \
		--project-name $(PROJECT_NAME) \
		--account-name $(ACCOUNT)
```

---

## New Scripts Required

### 1. `rotate_intermediate.py`

**Purpose:** Generate new Intermediate CA signed by existing Root CA

**Inputs:**
- Root CA fetched from SSM Parameter Store
- Configuration from environment

**Outputs:**
- `ca_operations/output/{env}/intermediate-ca/IntermediateCA.key`
- `ca_operations/output/{env}/intermediate-ca/IntermediateCA.pem`
- `ca_operations/output/{env}/truststore/truststore.pem`

**Key Logic:**
```python
# Pseudocode
def rotate_intermediate(project_name: str, account_name: str):
    # 1. Fetch Root CA from SSM
    root_private_key = ssm.get_parameter(f"/{project}/{account}/ca/root/private-key", decrypt=True)
    root_certificate = ssm.get_parameter(f"/{project}/{account}/ca/root/certificate")

    # 2. Generate new Intermediate key pair
    intermediate_key = generate_rsa_key(4096)

    # 3. Create and sign Intermediate certificate
    intermediate_cert = create_intermediate_ca(
        private_key=intermediate_key,
        signing_key=root_private_key,
        issuer_cert=root_certificate,
        validity_years=5
    )

    # 4. Write to output directory
    write_outputs(intermediate_key, intermediate_cert)

    # 5. Create truststore bundle
    create_truststore(intermediate_cert, root_certificate)
```

### 2. `reprovision_all_clients.py`

**Purpose:** Revoke old certs and issue new ones for all clients

**Inputs:**
- Client list from `clients/{env}.json`
- New Intermediate CA from local filesystem (just generated)

**Outputs:**
- Updated SSM parameters for each client
- Updated DynamoDB metadata (old revoked, new active)

### 3. `verify_mtls.py`

**Purpose:** Automated verification of mTLS after rotation

**Tests:**
- New client cert + new key → 200 OK
- Old client cert (if available) → 403 Forbidden
- Invalid cert → 403 Forbidden

---

## Rollback Strategy

**Important:** In a compromise scenario, rollback is NOT recommended.

However, if rotation was triggered by mistake:

1. **S3 Versioning:** Restore previous `truststore.pem` version
2. **SSM Parameter Store:** Use parameter version history
3. **DynamoDB:** Revert status changes (revoked → active)
4. **Re-run Terraform:** `make tf-apply STACK=certificate-bootstrap`

---

## Timing Estimates

| Phase | Duration | Notes |
|-------|----------|-------|
| Generate new Intermediate | ~10 seconds | RSA 4096 key generation |
| Terraform truststore deploy | ~30 seconds | S3 upload + SSM update |
| Per-client re-provision | ~5 seconds each | Key gen + SSM + DynamoDB |
| API Gateway truststore refresh | ~60 seconds | Automatic, no action needed |
| **Total (10 clients)** | **~3-4 minutes** | End-to-end rotation |

---

## Security Considerations

### Access Control
- Workflow requires `workflow_dispatch` with confirmation
- Uses separate GitHub environment with approval gates (recommended)
- IAM role should have minimum required permissions

### Audit Trail
- S3 versioning captures truststore history
- DynamoDB retains revoked cert metadata
- CloudWatch Logs for all API calls
- GitHub Actions logs for workflow execution

### Secrets Handling
- Root CA private key only accessed during rotation (not stored locally)
- New Intermediate private key written to filesystem temporarily
- All local artifacts cleaned after pipeline completion

---

## Testing the Rotation Process

### Pre-Production Validation

1. **Sandbox Environment:**
   - Run full rotation in sandbox first
   - Verify all clients re-provisioned
   - Test mTLS connectivity

2. **Dry-Run Mode (Future Enhancement):**
   - Add `--dry-run` flag to scripts
   - Validates all steps without making changes

3. **Load Testing:**
   - Ensure rotation doesn't cause API downtime
   - API Gateway truststore refresh is atomic

---

## Open Questions for Validation

1. **Client Certificate Distribution:**
   - How are new client certs delivered to API consumers?
   - Is there an automated distribution mechanism?
   - Consider: Secure email, API endpoint, manual handoff?

2. **Grace Period:**
   - Should there be any grace period for non-compromise rotations (scheduled rotation)?
   - For compromise: Hard cutover recommended

3. **Notification System:**
   - What channels should receive rotation notifications?
   - Who needs to be informed when rotation completes?

4. **Multi-Region Consideration:**
   - Is API Gateway deployed in multiple regions?
   - Need to ensure truststore update propagates to all regions?

5. **Client Acknowledgment:**
   - Should there be a mechanism for clients to confirm they received new certs?
   - DynamoDB status field: `active` → `acknowledged`?

---

## Summary

This strategy enables a **one-click emergency response** to Intermediate CA compromise:

```bash
# One-click rotation (GitHub Actions)
gh workflow run rotate-intermediate-ca.yml \
  -f environment=production \
  -f confirm_rotation=ROTATE
```

**Key Benefits:**
- Root CA remains untouched (10-year validity preserved)
- All client certs automatically re-provisioned
- Hard cutover ensures no window for attacker-issued certs
- Full audit trail maintained
- Minimal downtime (~60 seconds for truststore refresh)

**Required Implementation:**
1. New Python script: `rotate_intermediate.py`
2. New Python script: `reprovision_all_clients.py`
3. New Python script: `verify_mtls.py`
4. New GitHub workflow: `rotate-intermediate-ca.yml`
5. New Makefile targets in `ca.mk`
