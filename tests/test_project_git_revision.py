"""Exercise the project revision probe against real, isolated Git workspaces."""

from pathlib import Path
import subprocess
import tempfile
import unittest
from uuid import uuid4

from tools.prepare_project_git import prepare_project_git
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
    def test_prepare_shared_project_and_resolve_its_first_commit_from_another_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            human, daimon, shared = (root / name for name in ("human", "daimon", "shared"))
            repository = uuid4()
            for workspace in (human, daimon):
                workspace.mkdir()
                (workspace / ".daimon-topic").write_text(workspace.name)
            shared.mkdir()
            shared.chmod(0o2770)

            with self.assertRaisesRegex(ValueError, "workspace claim changed"):
                prepare_project_git(human, "stale", "story", repository, shared)
            self.assertEqual(list(shared.iterdir()), [])
            first = prepare_project_git(human, "human", "story", repository, shared)
            checkout = human / "story"
            scene = checkout / "scene.md"
            scene.write_text("The traveler opens the door onto the garden.\n")
            _git(checkout, "add", "--", "scene.md")
            _git(checkout, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "First scene")
            _git(checkout, "push", "origin", "HEAD:refs/heads/main")
            exact = _git(checkout, "rev-parse", "HEAD")

            scene.write_text("An unfinished revision stays here.\n")
            _git(checkout, "add", "--", "scene.md")
            staged = _git(checkout, "diff", "--cached")
            second = prepare_project_git(daimon, "daimon", "reading", repository, shared)
            self.assertEqual(first["locator"], second["locator"])
            self.assertEqual(verify_project_revision(daimon / "reading", exact)["commit"], exact)
            self.assertIn("traveler", (daimon / "reading" / "scene.md").read_text())
            readback = prepare_project_git(human, "human", "story", repository, shared)
            self.assertFalse(readback["created_checkout"])
            self.assertEqual(staged, _git(checkout, "diff", "--cached"))
            with self.assertRaisesRegex(ValueError, "different Git origin"):
                prepare_project_git(human, "human", "story", uuid4(), shared)
            self.assertEqual(len(list(shared.iterdir())), 1)

    def test_prepare_local_project_reuses_identity_and_never_initializes_an_occupied_path(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            (workspace / ".daimon-topic").write_text("current")
            repository = uuid4()
            result = prepare_project_git(workspace, "current", "story", repository)
            self.assertEqual(result["locator"], f"git:local:{repository}")
            self.assertFalse(prepare_project_git(workspace, "current", "story", repository)["created_checkout"])
            with self.assertRaisesRegex(ValueError, "different local repository identity"):
                prepare_project_git(workspace, "current", "story", uuid4())
            draft = workspace / "existing"
            draft.mkdir()
            (draft / "chapter.md").write_text("Keep my draft.")
            with self.assertRaisesRegex(ValueError, "Git rev-parse failed"):
                prepare_project_git(workspace, "current", "existing", uuid4())
            self.assertEqual(list(draft.iterdir()), [draft / "chapter.md"])
            with self.assertRaisesRegex(ValueError, "project directory"):
                prepare_project_git(workspace, "current", "../outside", uuid4())

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
