#!/usr/bin/env python3
"""Generate HS256 JWT token for ioc-api-gateway performance tests."""

import argparse
import base64
import hashlib
import hmac
import json
import time


def b64url_json(payload: dict) -> bytes:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def generate_token(secret: str, expires_in: int = 3600) -> str:
    now = int(time.time())

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "user_id": "perf-test-user",
        "username": "perf-test",
        "roles": ["tester", "admin"],
        "iss": "ioc-api-gateway",
        "iat": now,
        "exp": now + expires_in,
    }

    message = b".".join([b64url_json(header), b64url_json(payload)])
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()
    sig_encoded = base64.urlsafe_b64encode(signature).rstrip(b"=")

    return (message + b"." + sig_encoded).decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate JWT for performance tests")
    parser.add_argument(
        "--secret",
        default=None,
        help="JWT secret key (defaults to JWT_SECRET env or compose default)",
    )
    parser.add_argument(
        "--expires-in",
        type=int,
        default=3600,
        help="Token lifetime in seconds (default: 3600)",
    )
    args = parser.parse_args()

    import os

    secret = args.secret or os.getenv("JWT_SECRET") or "test-secret-key-do-not-use-in-production"
    print(generate_token(secret=secret, expires_in=args.expires_in))


if __name__ == "__main__":
    main()
