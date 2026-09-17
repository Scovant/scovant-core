"""Vendor-shaped credential patterns. The SAME nine strings the monorepo's publish
guard uses; a Cloud test pins the two tables equal so they cannot drift."""
VENDOR_PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "scovant_api_token": r"\bscvt_[A-Za-z0-9_-]{8,}",
    "paddle_key": r"\bpdl_[A-Za-z0-9_]{8,}",
    "github_token": r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
    "slack_token": r"\bxox[bp]-[A-Za-z0-9-]{10,}",
    "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}",
    "openai_style_key": r"\bsk-[A-Za-z0-9]{20,}",
    "private_key_block": r"-----BEGIN [A-Z ]*PRIVATE KEY",
    "jwt": r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}",
}
