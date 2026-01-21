# End-to-end encryption example

## 1. How to run locally

- First, generate key pair:

```(sh)
chmod +x backend/generate_keys.sh && ./backend/generate_keys.sh
```

- Build and run dockerfile:

```(sh)
docker build -t e2ee:<tag> .
docker run -p 8000:8000 --rm --tty e2ee:<tag>
```

- Access the web frontend on `http://localhost:8000`

## 2. Considerations

### 2.1. Key Rotation Strategy

> Design a zero-downtime strategy to migrate millions of records to the new Data Encryption Key (DEK). How does the system know which key to use for decryption during the transition period?

1. Preparation: add key version column to DB (e.g. `key_version int default 1`). Add multi-version support to encryption & search functions.
2. Generate new DEK_v2 and store in vault.
3. Create a background job to process in batches:
   1. Select candidates to update: `SELECT * FROM tbl_name WHERE key_version = 1 LIMIT <batch_size>`.
   2. For each record, decrypt using DEK_v1, then recompute encrypted values and corresponding blind indices using DEK_v2. Save new records in a staging table to not screw up the current data first.
   3. Post-check: assert that DEK_v2 records created are compatible with search logic by using existing search function to test that the correct record can be retrieved.
   4. Replace key_version and encrypted data into original table.
4. Decryption during transitional period:
   1. On new record storage, use DEK_v2 directly.
   2. On search: compute blind index -> fetch candidates -> attempt decryption loop as before, prioritizing DEK_v2 and fallback to DEK_v1 if fails. Cache successful DEK per record ID (TTL ~1hr) in Redis to minimize vault calls
5. When migration finishes (no more record with `key_version = 1`), invalidate cached DEK per record ID and remove DEK_v1 from vault.

--> Consider to drop support for multi-version key, but may as well just keep the support to use next year.

### 2.2. Data Leak Incident Response

> A security audit reveals that a developer accidentally logged the 'Decrypted National ID' into our Cloud Logigng system (e.g., CloudWatch/Stackdriver) for the past 24 hours.
> As a Tech Senior Backend Developer, what are your immediate actions? How do you remediate the leak, and what technical controls would you implement to prevent this from happening again?

#### 2.2.1. Immediate Actions (0-2 Hours)

1. **Quarantine Logging Endpoint**: Rotate CloudWatch log group/stream keys immediately and revoke developer IAM access to the affected log group
2. **Assemble Incident Response Team**: Notify CISO, Legal, DPO, and affected service owner within 15 minutes
3. **Preserve Evidence**: Create read-only snapshot of affected CloudWatch log group before any deletion
4. **Scope Impact**: Query CloudWatch logs for `national_id` regex patterns (`\d{9,12}`) across all streams in affected group
5. **Classify Severity**: Determine count of unique National IDs exposed and retention period (24h vs. longer)

#### 2.2.2. Leak Remediation (2-24 Hours)

##### Data Containment

```(shell)
# CloudWatch: Delete affected logs (Legal-approved)
aws logs delete-retention-policy --log-group-name /app/e2ee-prod
aws logs put-retention-policy --log-group-name /app/e2ee-prod --retention-in-days 1

# Rotate all logging credentials
IAM Policy: Deny logs:PutLogEvents for affected group
```

##### Notification Protocol

- **< 100 IDs**: Internal notification only (Legal review)
- **100-1000 IDs**: Mandatory notification to privacy authorities (72h window)  
- **> 1000 IDs**: Executive notification + public disclosure preparation

##### Affected Party Actions

```python
# Generate tokenization map for compromised IDs
compromised_ids = cloudwatch_query_national_ids()
for nid in compromised_ids:
    generate_new_token(nid)  # Re-tokenize in DB
    notify_user_async(nid, "Security incident - new ID token issued")
```

#### 2.2.3. Prevention Measures (Technical Controls)

##### 1. **Zero-Trust Logging** (Immediate)

```python
# PII Redaction Filter (Structurized Logging)
class PIIFilter(logging.Filter):
    PII_PATTERNS = [r'\b\d{9,12}\b', r'4[0-9]{12}(?:[0-9]{3})?']  # NationalID, CC
    
    def filter(self, record):
        for pattern in self.PII_PATTERNS:
            record.msg = re.sub(pattern, '[REDACTED]', str(record.msg))
        return True

# CloudWatch Agent Config
logging.getLogger().addFilter(PIIFilter())
```

##### 2. **Data Classification Enforcement**

```python
# Context-aware logging wrapper
class SecureLogger:
    SENSITIVE_KEYS = {'national_id', 'card_number', 'ssn'}
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def debug(self, msg: str, sensitive_data: dict = None):
        if sensitive_data:
            redacted = {k: '[REDACTED]' if k in self.SENSITIVE_KEYS else v 
                       for k,v in sensitive_data.items()}
            self.logger.debug(msg, extra={'data': redacted})
        else:
            self.logger.debug(msg)
```

##### 3. **Runtime PII Detection** (Production)

```python
# DecryptService wrapper with audit logging only
class AuditDecryptService(DecryptService):
    async def decrypt(self, payload: EncryptedPayload):
        plaintext = await super().decrypt(payload)  # In-memory only
        
        # NEVER log decrypted content
        await self.audit_access(payload.user_id, payload.recipient_id)
        return plaintext  # Return without logging
```

##### 4. **Infrastructure Controls**

CloudWatch Log Group Policy:

- Retention: 7 days max
- KMS Encryption: Mandatory
- Access: Least privilege IAM roles only
- Subscription Filter → S3 (immutable backup)

##### 5. **Developer Experience Prevention**

```typescript
// Frontend: Type-safe logging
const logger = {
  error: (msg: string, metadata?: Record<string, string | number>) => {
    // Strip PII keys automatically
    const safeMeta = Object.fromEntries(
      Object.entries(metadata || {}).filter(([k]) => !PII_KEYS.has(k))
    );
    console.error(msg, safeMeta);
  }
};
```

##### 6. **CI/CD Pipeline Checks**

```yaml
# GitHub Actions / GitLab CI
- name: PII Scan
  uses: actions/pii-scanner@v1
  with:
    paths: 'src/**/decrypt_service.py'
    patterns: national_id,card_number
```

##### 7. **Monitoring & Alerting**

```(plaintext)
Alert Rules:
1. "national_id" OR "\d{9,12}" in logs → Critical → PagerDuty
2. DecryptService.decrypt() called > 100/min → Warning  
3. CloudWatch PutLogEvents > 10k/min → Throttle
```

#### Implementation Priority (Next 48h)

```(plaintext)
1. [URGENT] Rotate CloudWatch credentials
2. [URGENT] Deploy PIIFilter to all loggers
3. [HIGH] Audit all decrypt points (4h)
4. [HIGH] Mandatory code review for logging changes (ongoing)
5. [MEDIUM] DLP integration (CloudWatch → S3 → scan → quarantine)
```

**Result**: Zero PII in logs, automatic redaction, developer guardrails, and full audit trail without compromising security.
