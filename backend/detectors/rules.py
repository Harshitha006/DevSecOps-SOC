import re

RULES = [
    {
        "name": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "HIGH"
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?i)aws(.{0,20})?(secret|access)[^\\n]{0,20}[A-Za-z0-9/+=]{40}",
        "severity": "CRITICAL"
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9-_]{16,}['\"]",
        "severity": "HIGH"
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "severity": "MEDIUM"
    },
]
