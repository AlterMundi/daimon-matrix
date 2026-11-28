"""Exercise the project revision probe against real, isolated Git workspaces."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.verify_project_git import verify_project_revision


def _git(directory: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(directory), *args],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return result.stdout.strip()


class ProjectGitRevisionTest(unittest.TestCase):
    def test_moved_workspace_recovers_commit_without_changing_local_drafts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "workspace-a"
            first.mkdir()
            _git(first, "init", "-q", "--initial-branch=main")
            story = first / "story.md"
            story.write_text("A visit to the patio.\n", encoding="utf-8")
            _git(first, "add", "--", "story.md")
            _git(
                first, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "-qm", "First readable scene",
            )
            commit = _git(first, "rev-parse", "HEAD")
            remote = root / "shared.git"
            _git(root, "init", "-q", "--bare", "--initial-branch=main", str(remote))
            _git(first, "push", str(remote), "HEAD:refs/heads/main")
            second = root / "workspace-b"
            _git(root, "clone", "-q", str(remote), str(second))
            moved = root / "moved-workspace"
            second.rename(moved)

            story.write_text("A local draft stays here.\n", encoding="utf-8")
            (first / "pending.md").write_text("A staged draft.\n", encoding="utf-8")
            _git(first, "add", "--", "pending.md")
            status = _git(first, "status", "--porcelain")
            index = _git(first, "diff", "--cached")
            expected = verify_project_revision(first, commit)
            self.assertEqual(expected["commit"], commit)
            self.assertEqual(verify_project_revision(moved, commit), expected)
            self.assertEqual(_git(moved, "show", f"{commit}:story.md"), "A visit to the patio.")

            absent = ("0" if commit[0] != "0" else "1") + commit[1:]
            with self.assertRaisesRegex(ValueError, "unavailable"):
                verify_project_revision(moved, absent)
            with self.assertRaisesRegex(ValueError, "full Git"):
                verify_project_revision(moved, "main")
            nested = moved / "notes"
            nested.mkdir()
            with self.assertRaisesRegex(ValueError, "exact project Git root"):
                verify_project_revision(nested, commit)

            self.assertEqual(verify_project_revision(first, commit), expected)
            self.assertEqual(_git(first, "rev-parse", "HEAD"), commit)
            self.assertEqual(_git(remote, "rev-parse", "HEAD"), commit)
            self.assertEqual(_git(first, "status", "--porcelain"), status)
            self.assertEqual(_git(first, "diff", "--cached"), index)
            self.assertEqual(story.read_text(encoding="utf-8"), "A local draft stays here.\n")
