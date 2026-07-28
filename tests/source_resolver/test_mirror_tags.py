from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MIRROR_SCRIPT = REPOSITORY_ROOT / "scripts" / "mirror-tags.sh"
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "mirror-auxiliary-sources.yml"


def find_bash():
  git = shutil.which("git")
  if os.name == "nt" and git:
    git_bash = Path(git).resolve().parent.parent / "bin" / "bash.exe"
    if git_bash.is_file():
      return str(git_bash)
  return shutil.which("bash")


BASH = find_bash()


def run_git(directory, *arguments):
  result = subprocess.run(
    ["git", *arguments],
    cwd=directory,
    capture_output=True,
    encoding="utf-8",
    errors="replace",
    check=False,
  )
  if result.returncode != 0:
    raise AssertionError(result.stderr or result.stdout)
  return result.stdout.strip()


def create_mirrors(root):
  checkout = Path(root) / "checkout"
  checkout.mkdir()
  run_git(checkout, "init")
  run_git(checkout, "config", "user.name", "JetOnlyOffice tests")
  run_git(checkout, "config", "user.email", "tests@jetonlyoffice.invalid")
  (checkout / "content.txt").write_text("one\n", encoding="utf-8", newline="\n")
  run_git(checkout, "add", "content.txt")
  run_git(checkout, "commit", "-m", "first")
  run_git(checkout, "tag", "tag-1")
  (checkout / "content.txt").write_text("two\n", encoding="utf-8", newline="\n")
  run_git(checkout, "commit", "-am", "second")
  run_git(checkout, "tag", "-a", "tag-2", "-m", "annotated")
  (checkout / "content.txt").write_text("three\n", encoding="utf-8", newline="\n")
  run_git(checkout, "commit", "-am", "third")
  run_git(checkout, "tag", "tag-3")
  source = Path(root) / "source.git"
  target = Path(root) / "target.git"
  run_git(root, "clone", "--mirror", str(checkout), str(source))
  run_git(root, "init", "--bare", str(target))
  return checkout, source, target


def tag_refs(repository):
  output = run_git(
    repository,
    "for-each-ref",
    "--sort=refname",
    "--format=%(refname) %(objectname)",
    "refs/tags",
  )
  return output.splitlines() if output else []


@unittest.skipUnless(BASH, "bash is not available")
class MirrorTagTests(unittest.TestCase):
  def run_script(self, source, target, batch_size="2"):
    return subprocess.run(
      [BASH, str(MIRROR_SCRIPT), str(source), str(target)],
      cwd=REPOSITORY_ROOT,
      env={**os.environ, "MIRROR_TAG_BATCH_SIZE": batch_size},
      capture_output=True,
      encoding="utf-8",
      errors="replace",
      check=False,
    )

  def test_pushes_missing_tags_in_atomic_batches_and_is_resumable(self):
    with tempfile.TemporaryDirectory() as directory:
      _, source, target = create_mirrors(directory)
      first = self.run_script(source, target)
      self.assertEqual(0, first.returncode, first.stderr)
      self.assertIn("source=3 target=0 pending=3 batches=2", first.stdout)
      self.assertEqual(tag_refs(source), tag_refs(target))

      second = self.run_script(source, target)
      self.assertEqual(0, second.returncode, second.stderr)
      self.assertIn("source=3 target=3 pending=0 batches=0", second.stdout)

  def test_rejects_divergent_target_tag_before_pushing_any_batch(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, source, target = create_mirrors(directory)
      run_git(checkout, "tag", "divergent", "tag-1")
      run_git(checkout, "push", str(target), "divergent:refs/tags/tag-2")

      result = self.run_script(source, target)
      self.assertEqual(3, result.returncode)
      self.assertIn("target tag differs: refs/tags/tag-2", result.stderr)
      self.assertEqual(["refs/tags/tag-2"], [line.split()[0] for line in tag_refs(target)])

  def test_rejects_unexpected_target_tag(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, source, target = create_mirrors(directory)
      run_git(checkout, "tag", "target-only")
      run_git(checkout, "push", str(target), "target-only:refs/tags/target-only")

      result = self.run_script(source, target)
      self.assertEqual(3, result.returncode)
      self.assertIn("target has unexpected tag refs/tags/target-only", result.stderr)

  def test_workflow_uses_pinned_tooling_and_bounded_tag_sync(self):
    workflow = WORKFLOW.read_text(encoding="utf-8")
    self.assertIn("max-parallel: 2", workflow)
    self.assertRegex(workflow, r"actions/checkout@[0-9a-f]{40}")
    self.assertIn("./scripts/mirror-tags.sh", workflow)
    self.assertIn("MIRROR_TAG_BATCH_SIZE=100", workflow)
    self.assertNotIn("push --mirror", workflow)
    self.assertNotIn("'refs/tags/*:refs/tags/*'", workflow)


if __name__ == "__main__":
  unittest.main()
