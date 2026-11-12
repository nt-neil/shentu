"""Print a SigV4 presigned PUT URL for one S3 object (stdlib only).

Usage: presign_put.py REGION BUCKET KEY EXPIRES_SECONDS
Credentials come from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
AWS_SESSION_TOKEN (optional) in the environment; nothing is written.
"""
import datetime
import hashlib
import hmac
import os
import sys
import urllib.parse


def sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def main():
    region, bucket, key, expires = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    ak, sk = os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"]
    token = os.environ.get("AWS_SESSION_TOKEN")
    host = f"{bucket}.s3.{region}.amazonaws.com"
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    scope = f"{day}/{region}/s3/aws4_request"
    path = "/" + urllib.parse.quote(key, safe="/~")
    q = {"X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": f"{ak}/{scope}",
         "X-Amz-Date": amz_date, "X-Amz-Expires": str(expires), "X-Amz-SignedHeaders": "host"}
    if token:
        q["X-Amz-Security-Token"] = token
    qs = "&".join(f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(v, safe='~')}" for k, v in sorted(q.items()))
    canonical = f"PUT\n{path}\n{qs}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
    to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
    k = sign(sign(sign(sign(("AWS4" + sk).encode(), day), region), "s3"), "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    print(f"https://{host}{path}?{qs}&X-Amz-Signature={sig}")


if __name__ == "__main__":
    main()
