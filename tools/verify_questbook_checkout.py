"""Read back one authorized Git-linked card and its original Questbook receipt."""

import argparse
import json
import subprocess
from pathlib import Path
from uuid import UUID

from verify_project_git import verify_project_revision


def identifier(value: str) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Expected a canonical project, card or operation UUID.")
    return value


def native_read(project: str, selection: dict) -> dict:
    arguments = {"project": project, **selection}
    reply = subprocess.run(
        ["holodeck-world", "--own", "questbook", "--json", json.dumps(arguments)],
        check=True, capture_output=True, timeout=20,
    )
    result = json.loads(reply.stdout)
    if (not isinstance(result, dict) or result.get("ok") is not True or result.get("authoritySource") != {
        "identity": "receiving-lane", "access": "current-being-grant",
    } or not isinstance(result.get("result"), dict)):
        raise ValueError("The current own-native lane did not confirm the read.")
    return result["result"]


def read_record(path: Path) -> dict:
    with path.open("rb") as file:
        encoded = file.read(256 * 1024 + 1)
    if len(encoded) > 256 * 1024:
        raise ValueError("Select one bounded project record or original receipt.")
    record = json.loads(encoded)
    if not isinstance(record, dict):
        raise ValueError("Expected a JSON object.")
    return record


def verify(checkout: Path, project_path: Path, receipt_path: Path) -> dict:
    selection = read_record(project_path)
    project = identifier(selection["project"])
    repository = identifier(selection["repository"])
    original = read_record(receipt_path)
    snapshot = original["card"]
    if snapshot["project"] != project:
        raise ValueError("The saved receipt belongs to a different project.")
    card = identifier(snapshot["id"])
    operation = identifier(original["command"]["operation"])
    if original["command"]["card"] != card:
        raise ValueError("The saved receipt has a different card identity.")
    revisions = [entry for entry in snapshot["evidence"] if entry["repository"] == repository]
    if len(revisions) != 1 or revisions[0]["commit"] != selection["commit"]:
        raise ValueError("The saved receipt does not select one revision for that repository.")
    evidence = revisions[0]
    git = verify_project_revision(checkout, evidence["commit"], expected_origin=selection["origin"])

    observed = native_read(project, {"type": "receipt", "operation": operation})
    if observed != original:
        raise ValueError("The receiving receipt differs from the saved original.")
    current = native_read(project, {"type": "read", "card": card})
    revision = snapshot["revision"]
    if (current["project"] != project or current["id"] != card
            or type(revision) is not int or type(current["revision"]) is not int
            or current["revision"] < revision):
        raise ValueError("The current card has a different identity or predates the original.")

    return {
        **git,
        "receipt_revision": revision,
        "current_revision": current["revision"],
        "card_status": current["status"],
        "original_git_link_is_current": evidence in current["evidence"],
        "receipt": "exact",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("project", type=Path)
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.checkout, args.project, args.receipt)
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        parser.exit(1, "Could not verify this checkout, card and original receipt.\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
