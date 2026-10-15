"""Exercise the actual desktop console protocol without opening a window."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "owner_setup"))
import owner_console

result = owner_console.signed_operation(
    os.environ["RATCHET_TEST_BASE"], Path(os.environ["RATCHET_TEST_OWNER_FILE"]),
    os.environ["RATCHET_TEST_OWNER_PASSWORD"], {"type": "accounts.list", "limit": 100},
)
assert isinstance(result.get("accounts"), list)
print(json.dumps({"native_console_verified": True, "accounts": len(result["accounts"])}))
