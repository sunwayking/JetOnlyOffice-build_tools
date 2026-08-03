import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from contracts.contract_tool import validate_contract  # noqa: E402
from source_resolver import (  # noqa: E402
  _download_anonymous_lfs_object,
  _fetch_anonymous_lfs_actions,
  LfsActionRefreshRequired,
  ResolutionError,
  audit_report,
  bind_source_tree_manifest,
  build_source_lock,
  caches_from_lock,
  fetch_lfs_objects,
  license_inventory_report,
  lfs_public_audit_report,
  main,
  materialize,
  policy_findings,
  repository_license_inventory,
  repository_metadata,
  selection_audit_report,
  sync_cache,
  validate_inputs,
  verify_materialized,
  verify_public_mirror,
  verify_relationships,
  verify_selections,
)


SHA1_A = "a" * 40
SHA1_B = "b" * 40


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


def repository_input(identifier, commit=SHA1_A):
  return {
    "id": identifier,
    "role": "build-input",
    "checkoutPath": f"sources/{identifier}",
    "origin": f"https://github.com/sunwayking/JetOnlyOffice-{identifier}.git",
    "upstream": f"https://github.com/ONLYOFFICE/{identifier}.git",
    "commit": commit,
    "refHint": "fixed test commit",
    "selection": {
      "type": "tag",
      "ref": "refs/tags/v1.0.0",
    },
    "projectFork": False,
    "buildInput": True,
    "active": True,
    "license": {
      "status": "declared",
      "path": "LICENSE",
      "spdx": "MIT",
    },
  }


def source_inputs():
  build_tools = repository_input("build-tools")
  del build_tools["commit"]
  build_tools["commitSource"] = "self"
  build_tools["selection"] = {"type": "self"}
  build_tools["role"] = "product-fork"
  build_tools["projectFork"] = True
  documentserver = repository_input("documentserver", SHA1_B)
  documentserver["role"] = "superproject"
  return {
    "schemaVersion": 1,
    "productVersion": "9.4.0",
    "releaseCutoff": 100,
    "baseline": {
      "repository": "documentserver",
      "commit": SHA1_B,
    },
    "repositories": [build_tools, documentserver],
    "relationships": [],
  }


def create_repository(root, name="source"):
  checkout = Path(root) / name
  checkout.mkdir()
  run_git(checkout, "init")
  run_git(checkout, "config", "user.name", "JetOnlyOffice tests")
  run_git(checkout, "config", "user.email", "tests@jetonlyoffice.invalid")
  (checkout / "LICENSE").write_text("test license\n", encoding="utf-8", newline="\n")
  (checkout / "content.txt").write_text("content\n", encoding="utf-8", newline="\n")
  run_git(checkout, "add", "LICENSE", "content.txt")
  run_git(checkout, "commit", "-m", "initial")
  commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
  bare = Path(root) / (name + ".git")
  run_git(root, "clone", "--bare", str(checkout), str(bare))
  return checkout, bare, commit


def create_source_lock(root, identifier="source"):
  _, bare, commit = create_repository(root, identifier)
  repository = repository_input(identifier, commit)
  record = repository_metadata(repository, bare, commit)
  lock = {
    "schemaVersion": 1,
    "lockType": "source",
    "productVersion": "9.4.0",
    "baseline": {"repository": identifier, "commit": commit},
    "sourceDateEpoch": record["commitTime"],
    "repositories": [record],
    "relationships": [],
  }
  bind_source_tree_manifest(lock, {identifier: bare})
  return repository, bare, commit, lock


def create_repository_evidence_fixture(root):
  payload = b"licensed font payload\n"
  mismatch = b"different font payload\n"
  license_text = b"GPL-2.0 license mapping\n"

  _, build_tools_bare, _ = create_repository(root, "build-tools")

  source_checkout, source_bare, _ = create_repository(root, "font-source")
  (source_checkout / "fonts").mkdir()
  (source_checkout / "fonts" / "Example.ttf").write_bytes(payload)
  run_git(source_checkout, "add", "fonts")
  run_git(source_checkout, "commit", "-m", "add source font")
  source_commit = run_git(source_checkout, "rev-parse", "HEAD^{commit}")
  run_git(
    source_bare,
    "fetch",
    str(source_checkout),
    f"{source_commit}:refs/heads/main",
  )

  evidence_checkout, evidence_bare, _ = create_repository(
    root, "license-evidence"
  )
  (evidence_checkout / "fonts").mkdir()
  (evidence_checkout / "fonts" / "Example.ttf").write_bytes(payload)
  (evidence_checkout / "fonts" / "Mismatch.ttf").write_bytes(mismatch)
  (evidence_checkout / "fonts" / "LICENSE.txt").write_bytes(license_text)
  run_git(evidence_checkout, "add", "fonts")
  run_git(evidence_checkout, "commit", "-m", "add reviewed evidence")
  evidence_commit = run_git(evidence_checkout, "rev-parse", "HEAD^{commit}")
  run_git(
    evidence_bare,
    "fetch",
    str(evidence_checkout),
    f"{evidence_commit}:refs/heads/main",
  )

  source = repository_input("font-source", source_commit)
  source["license"] = {
    "status": "component-scoped",
    "payloadPatterns": ["**/*.ttf"],
    "patterns": ["**/LICENSE*"],
    "reason": "The exact external evidence mapping is reviewed.",
    "reviewedComponents": [{
      "id": "fonts",
      "spdx": "GPL-2.0-only",
      "evidence": [{
        "type": "repository-git-blob",
        "path": "fonts/Example.ttf",
        "repository": "license-evidence",
        "referencePath": "fonts/Example.ttf",
        "locator": "fonts/LICENSE.txt",
        "sha256": hashlib.sha256(license_text).hexdigest(),
      }],
    }],
    "unresolvedComponents": [],
  }
  evidence = repository_input("license-evidence", evidence_commit)
  evidence["role"] = "auxiliary-mirror"
  evidence["license"] = {
    "status": "component-scoped",
    "payloadPatterns": ["**/*.ttf"],
    "patterns": ["**/LICENSE*"],
    "reason": "Every mirrored payload has an in-tree license mapping.",
    "reviewedComponents": [{
      "id": "fonts",
      "spdx": "GPL-2.0-only",
      "evidence": [
        {
          "type": "git-blob",
          "path": path,
          "locator": "fonts/LICENSE.txt",
          "sha256": hashlib.sha256(license_text).hexdigest(),
        }
        for path in ["fonts/Example.ttf", "fonts/Mismatch.ttf"]
      ],
    }],
    "unresolvedComponents": [],
  }
  build_tools = repository_input("build-tools")
  del build_tools["commit"]
  build_tools["commitSource"] = "self"
  build_tools["selection"] = {"type": "self"}
  build_tools["role"] = "product-fork"
  build_tools["projectFork"] = True
  inputs = {
    "schemaVersion": 1,
    "productVersion": "9.4.0",
    "releaseCutoff": 2000000000,
    "baseline": {"repository": "font-source", "commit": source_commit},
    "repositories": [build_tools, source, evidence],
    "relationships": [],
  }
  inputs["repositories"].sort(key=lambda item: item["id"])
  caches = {
    "build-tools": build_tools_bare,
    "font-source": source_bare,
    "license-evidence": evidence_bare,
  }
  for repository in inputs["repositories"]:
    run_git(
      caches[repository["id"]],
      "remote",
      "set-url",
      "origin",
      repository["origin"],
    )
  return inputs, caches, payload, license_text


def font_with_license_name(license_text):
  encoded = license_text.encode("utf-16-be")
  name_table = (
    struct.pack(">HHH", 0, 1, 18)
    + struct.pack(">HHHHHH", 3, 1, 0x0409, 13, len(encoded), 0)
    + encoded
  )
  return (
    struct.pack(">IHHHH", 0x00010000, 1, 0, 0, 0)
    + struct.pack(">4sIII", b"name", 0, 28, len(name_table))
    + name_table
  )


def add_lfs_object(root, checkout, name="asset.bin", content=b"locked lfs content\n"):
  oid = hashlib.sha256(content).hexdigest()
  pattern = Path(name).name
  (checkout / ".gitattributes").write_text(
    f"{pattern} filter=lfs diff=lfs merge=lfs -text\n",
    encoding="utf-8",
    newline="\n",
  )
  (checkout / name).write_text(
    "version https://git-lfs.github.com/spec/v1\n"
    f"oid sha256:{oid}\n"
    f"size {len(content)}\n",
    encoding="utf-8",
    newline="\n",
  )
  run_git(checkout, "add", ".gitattributes", name)
  run_git(checkout, "commit", "-m", "add lfs pointer")
  commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
  bare = Path(root) / "lfs-source.git"
  run_git(root, "clone", "--bare", str(checkout), str(bare))
  object_path = bare / "lfs" / "objects" / oid[:2] / oid[2:4] / oid
  object_path.parent.mkdir(parents=True)
  object_path.write_bytes(content)
  return bare, commit, oid, content


class SourceResolverTests(unittest.TestCase):
  def test_repository_selection_policy_is_explicit_and_fail_closed(self):
    value = source_inputs()
    validate_inputs(value)

    del value["repositories"][1]["selection"]
    with self.assertRaisesRegex(ResolutionError, "missing properties: selection"):
      validate_inputs(value)

    value = source_inputs()
    value["repositories"][1]["selection"] = {
      "type": "cutoff",
      "refPrefix": "refs/heads/main",
    }
    with self.assertRaisesRegex(ResolutionError, "official upstream head prefix"):
      validate_inputs(value)

    value = source_inputs()
    value["repositories"][1]["selection"] = {
      "type": "branch",
      "ref": "refs/heads/main",
    }
    with self.assertRaisesRegex(ResolutionError, "develop branch ref"):
      validate_inputs(value)

    value["repositories"][1]["selection"]["ref"] = "refs/heads/develop"
    with self.assertRaisesRegex(ResolutionError, "reserved for project forks"):
      validate_inputs(value)

    value = source_inputs()
    value["repositories"][1]["selection"] = {
      "type": "gitlink",
      "parent": "build-tools",
      "path": "missing",
    }
    with self.assertRaisesRegex(ResolutionError, "does not match a declared relationship"):
      validate_inputs(value)

  def test_selection_verification_resolves_branch_tag_gitlink_cutoff_and_self(self):
    with tempfile.TemporaryDirectory() as directory:
      _, branch_bare, branch_commit = create_repository(directory, "branch")
      run_git(branch_bare, "update-ref", "refs/heads/develop", branch_commit)

      parent_checkout, _, _ = create_repository(directory, "parent")
      child_checkout, child_bare, child_commit = create_repository(directory, "child")
      run_git(
        parent_checkout,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{child_commit},child",
      )
      run_git(parent_checkout, "commit", "-m", "lock child")
      parent_commit = run_git(parent_checkout, "rev-parse", "HEAD^{commit}")
      run_git(parent_checkout, "tag", "v1.0.0")
      parent_bare = Path(directory) / "parent-final.git"
      run_git(directory, "clone", "--bare", str(parent_checkout), str(parent_bare))

      tag_checkout, tag_bare, tag_commit = create_repository(directory, "tagged")
      run_git(tag_checkout, "tag", "v1.0.0")
      run_git(tag_bare, "fetch", str(tag_checkout), "refs/tags/v1.0.0:refs/tags/v1.0.0")

      cutoff_checkout, cutoff_bare, cutoff_commit = create_repository(directory, "cutoff")
      run_git(
        cutoff_bare,
        "update-ref",
        "refs/heads/upstream/main",
        cutoff_commit,
      )

      inputs = {
        "releaseCutoff": int(run_git(cutoff_bare, "show", "-s", "--format=%ct", cutoff_commit)) + 1,
        "relationships": [{
          "parent": "parent",
          "child": "child",
          "path": "child",
          "mode": "160000",
        }],
        "repositories": [
          {
            "id": "branch",
            "selection": {"type": "branch", "ref": "refs/heads/develop"},
          },
          {"id": "build-tools", "selection": {"type": "self"}},
          {
            "id": "child",
            "selection": {"type": "gitlink", "parent": "parent", "path": "child"},
          },
          {
            "id": "cutoff",
            "selection": {"type": "cutoff", "refPrefix": "refs/heads/upstream/"},
          },
          {"id": "parent", "selection": {"type": "tag", "ref": "refs/tags/v1.0.0"}},
          {"id": "tagged", "selection": {"type": "tag", "ref": "refs/tags/v1.0.0"}},
        ],
      }
      caches = {
        "branch": branch_bare,
        "child": child_bare,
        "cutoff": cutoff_bare,
        "parent": parent_bare,
        "tagged": tag_bare,
      }
      commits = {
        "branch": branch_commit,
        "build-tools": SHA1_A,
        "child": child_commit,
        "cutoff": cutoff_commit,
        "parent": parent_commit,
        "tagged": tag_commit,
      }

      records = verify_selections(inputs, caches, commits)

      self.assertEqual(
        ["branch", "build-tools", "child", "cutoff", "parent", "tagged"],
        [record["repository"] for record in records],
      )
      self.assertEqual("refs/heads/develop", records[0]["ref"])
      self.assertEqual("refs/heads/upstream/main", records[3]["resolvedRef"])

      commits["branch"] = SHA1_B
      with self.assertRaisesRegex(ResolutionError, "branch does not resolve"):
        verify_selections(inputs, caches, commits)
      commits["branch"] = branch_commit

      commits["tagged"] = SHA1_B
      with self.assertRaisesRegex(ResolutionError, "tag does not resolve"):
        verify_selections(inputs, caches, commits)

  def test_selection_audit_rejects_index_flags_hiding_self_changes(self):
    expected_origin = (
      "https://github.com/sunwayking/JetOnlyOffice-build-tools-self.git"
    )
    inputs = {
      "productVersion": "9.4.0",
      "releaseCutoff": 100,
      "repositories": [{
        "id": "build-tools",
        "origin": expected_origin,
        "commitSource": "self",
        "selection": {"type": "self"},
      }],
      "relationships": [],
    }
    for flag in ("--skip-worktree", "--assume-unchanged"):
      with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
        checkout, _, _ = create_repository(directory)
        run_git(checkout, "remote", "add", "origin", expected_origin)
        run_git(checkout, "update-index", flag, "content.txt")
        (checkout / "content.txt").write_text("hidden change\n", encoding="ascii")

        with self.assertRaisesRegex(ResolutionError, "unsafe Git index flag"):
          selection_audit_report(
            inputs,
            Path(directory) / "cache",
            checkout,
          )

  def test_cache_sync_prunes_tags_removed_from_the_public_mirror(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, remote, commit = create_repository(directory, "tag-prune")
      run_git(checkout, "tag", "obsolete")
      run_git(remote, "fetch", str(checkout), "refs/tags/obsolete:refs/tags/obsolete")
      repository = repository_input("tag-prune", commit)
      repository["origin"] = str(remote)
      cache_root = Path(directory) / "cache"

      with patch("source_resolver.verify_public_mirror"):
        cache = sync_cache(repository, cache_root, commit)
        self.assertEqual(commit, run_git(cache, "rev-parse", "refs/tags/obsolete^{commit}"))
        run_git(remote, "update-ref", "-d", "refs/tags/obsolete")
        sync_cache(repository, cache_root, commit)

      result = subprocess.run(
        ["git", "rev-parse", "--verify", "refs/tags/obsolete^{commit}"],
        cwd=cache,
        capture_output=True,
        check=False,
      )
      self.assertNotEqual(0, result.returncode)

  def test_repository_policy_is_strict_and_mirror_only(self):
    value = source_inputs()
    validate_inputs(value)
    value = source_inputs()
    value["repositories"][0]["origin"] = "https://github.com/ONLYOFFICE/build_tools.git"
    with self.assertRaisesRegex(ResolutionError, "sunwayking JetOnlyOffice mirror"):
      validate_inputs(value)
    value = source_inputs()
    value["repositories"][1]["branch"] = "develop"
    with self.assertRaisesRegex(ResolutionError, "unknown properties: branch"):
      validate_inputs(value)

    for invalid_expression in ("NOASSERTION", "TBD", "MIT OR", " "):
      value = source_inputs()
      value["repositories"][0]["license"]["spdx"] = invalid_expression
      with self.assertRaisesRegex(ResolutionError, "reviewed source set"):
        validate_inputs(value)

    value = source_inputs()
    value["repositories"][1]["checkoutPath"] = "C:/outside"
    with self.assertRaisesRegex(ResolutionError, "normalized and relative"):
      validate_inputs(value)

  def test_current_policy_fails_closed_on_license_gaps(self):
    value = json.loads(
      (REPOSITORY_ROOT / "locks" / "source-inputs.v1.json").read_text(encoding="utf-8")
    )
    validate_inputs(value)
    repositories_by_id = {
      repository["id"]: repository for repository in value["repositories"]
    }
    self.assertEqual(
      "671c834813f8644f68e63ee28859d5aace5e9aa2",
      repositories_by_id["documentserver"]["commit"],
    )
    self.assertEqual(
      {"type": "branch", "ref": "refs/heads/develop"},
      repositories_by_id["documentserver"]["selection"],
    )
    self.assertEqual(
      "dc623fe01acd54c91a9a34a0badf52d5df374b7a",
      repositories_by_id["sdkjs"]["commit"],
    )
    self.assertEqual(
      "556883bc4fa13e6aef9247441e4477f27102ff60",
      repositories_by_id["web-apps"]["commit"],
    )
    findings = policy_findings(value)
    self.assertEqual(
      ["build-tools-data", "core-fonts", "dictionaries"],
      [finding["repository"] for finding in findings],
    )
    report = audit_report(value)
    self.assertEqual("failed", report["status"])
    self.assertTrue(all(finding["code"] == "LICENSE_INCOMPLETE" for finding in findings))
    self.assertEqual(
      [
        "az_Latn_AZ",
        "da_DK", "el_GR", "en_AU",
        "hr_HR", "id_ID", "it_IT", "kk_KZ",
        "lt_LT", "mn_MN", "pl_PL", "pt_BR", "pt_PT",
        "ru_RU", "sl_SI", "uk_UA", "uz_Cyrl_UZ",
        "uz_Latn_UZ",
      ],
      next(
        finding["unresolvedComponents"]
        for finding in findings
        if finding["repository"] == "dictionaries"
      ),
    )
    self.assertEqual(
      ["cef", "python", "qt"],
      next(
        finding["unresolvedComponents"]
        for finding in findings
        if finding["repository"] == "build-tools-data"
      ),
    )
    build_tools_data = repositories_by_id["build-tools-data"]
    self.assertEqual(
      [
        "cef/5414/linux_64/cef_binary.7z",
        "python/python3.tar.gz",
        "qt/qt_binary_5.9.9_gcc_64.7z",
      ],
      build_tools_data["license"]["payloadPatterns"],
    )
    build_tools_blockers = {
      review["id"]: review
      for review in build_tools_data["license"]["blockingReviews"]
    }
    expected_build_tools_blockers = {
      "cef": (
        "cef/5414/linux_64/cef_binary.7z",
        "dff9aa53c147fd0c6a03f57e17aef10b0cee3fe7c4dc18b3b1a8a7a20bf0a145",
      ),
      "python": (
        "python/python3.tar.gz",
        "c251fd88959ad83a64711d37d7897d0bf7a3ed272f23b6ef6216e0eed0bf9360",
      ),
      "qt": (
        "qt/qt_binary_5.9.9_gcc_64.7z",
        "2602239b1040af3ff1ee889b77740ef2c5f80a5eebb8630acf4d1d1dea900415",
      ),
    }
    self.assertEqual(
      sorted(expected_build_tools_blockers), sorted(build_tools_blockers)
    )
    for component_id, (path, sha256) in expected_build_tools_blockers.items():
      review = build_tools_blockers[component_id]
      self.assertEqual("INCOMPLETE_SCOPE", review["code"])
      self.assertEqual(
        [{"path": path, "sha256": sha256}], review["evidence"]
      )
    self.assertEqual(
      ["ASC.ttf", "liberation"],
      next(
        finding["unresolvedComponents"]
        for finding in findings
        if finding["repository"] == "core-fonts"
      ),
    )
    self.assertEqual(
      {
        "type": "tag",
        "ref": "refs/tags/v9.4.0-evidence.3",
      },
      repositories_by_id["license-evidence"]["selection"],
    )
    self.assertEqual(
      "43308c6939597145e0387daded3cba2a481641be",
      repositories_by_id["license-evidence"]["commit"],
    )
    evidence_repository = repositories_by_id["license-evidence"]
    self.assertEqual(
      ["**/*.aff", "**/*.dic", "**/*.ttf"],
      evidence_repository["license"]["payloadPatterns"],
    )
    self.assertEqual(
      [
        "**/*.tex", "**/*.txt", "**/COPYING*", "**/COPYRIGHT", "**/LICENSE*"
      ],
      evidence_repository["license"]["patterns"],
    )
    self.assertEqual(
      [
        "de_AT",
        "de_CH",
        "de_DE",
        "en_GB",
        "fonts-beng-extra",
        "fonts-gujr-extra",
        "kacst",
        "kacst-one",
      ],
      [
        component["id"]
        for component in evidence_repository["license"]["reviewedComponents"]
      ],
    )
    german_spdx = (
      "(GPL-2.0-only OR GPL-3.0-only) AND "
      "LGPL-2.0-or-later AND LPPL-1.0"
    )
    for locale in ("de_AT", "de_CH", "de_DE"):
      evidence_component = next(
        component
        for component in evidence_repository["license"]["reviewedComponents"]
        if component["id"] == locale
      )
      self.assertEqual(german_spdx, evidence_component["spdx"])
      self.assertEqual(
        [
          (f"{locale}/{locale}.aff", f"{locale}/README_de_DE_frami.txt"),
          (f"{locale}/{locale}.dic", f"{locale}/README_de_DE_frami.txt"),
          (f"{locale}/hyph_{locale}.dic", f"{locale}/README_hyph_de.txt"),
        ],
        [
          (record["path"], record["locator"])
          for record in evidence_component["evidence"]
        ],
      )
    evidence_en_gb = next(
      component
      for component in evidence_repository["license"]["reviewedComponents"]
      if component["id"] == "en_GB"
    )
    self.assertEqual(
      "LGPL-3.0-only AND LicenseRef-Hyphen-en-GB-2011-10-07",
      evidence_en_gb["spdx"],
    )
    self.assertEqual(
      [
        ("en_GB/en_GB.aff", "en_GB/lgpl-3.0.txt", []),
        ("en_GB/en_GB.dic", "en_GB/lgpl-3.0.txt", []),
        (
          "en_GB/hyph_en_GB.dic",
          "en_GB/README_hyph_en_GB.txt",
          ["LicenseRef-Hyphen-en-GB-2011-10-07"],
        ),
      ],
      [
        (record["path"], record["locator"], record["licenseRefs"])
        for record in evidence_en_gb["evidence"]
      ],
    )
    self.assertEqual(
      ["ASC.ttf", "liberation"],
      [
        review["id"]
        for review in repositories_by_id["core-fonts"]["license"][
          "blockingReviews"
        ]
      ],
    )
    core_fonts = next(
      repository
      for repository in value["repositories"]
      if repository["id"] == "core-fonts"
    )
    self.assertEqual(
      [
        "abyssinica",
        "ancient-scripts",
        "arphic-ukai",
        "asana",
        "caladea",
        "crosextra",
        "dejavu",
        "droid",
        "fonts-beng-extra",
        "fonts-gujr-extra",
        "fonts-telu-extra",
        "freefont",
        "kacst",
        "kacst-one",
        "lohit-assamese",
        "lohit-bengali",
        "lohit-devanagari",
        "lohit-gujarati",
        "lohit-kannada",
        "lohit-malayalam",
        "lohit-oriya",
        "lohit-punjabi",
        "lohit-tamil",
        "lohit-tamil-classical",
        "lohit-telugu",
        "nanum",
        "noto",
        "openoffice",
        "opensans",
        "padauk",
        "samyak",
        "samyak-fonts",
        "takao-gothic",
        "tibetan-machine",
        "ttf-khmeros-core",
        "ubuntu-font-family",
        "wqy-zenhei",
      ],
      [component["id"] for component in core_fonts["license"]["reviewedComponents"]],
    )
    reviewed_by_id = {
      component["id"]: component
      for component in core_fonts["license"]["reviewedComponents"]
    }
    expected_component_licenses = {
      "abyssinica": ("OFL-1.1", 1),
      "ancient-scripts": (
        "LicenseRef-Unicode-Fonts-for-Ancient-Scripts", 1
      ),
      "arphic-ukai": ("Arphic-1999", 1),
      "asana": ("OFL-1.1", 1),
      "caladea": ("Apache-2.0", 4),
      "crosextra": ("OFL-1.1", 4),
      "dejavu": ("Bitstream-Vera AND LicenseRef-AMSFonts", 22),
      "droid": ("Apache-2.0", 1),
      "fonts-beng-extra": ("GPL-2.0-or-later", 6),
      "fonts-gujr-extra": ("GPL-2.0-or-later", 2),
      "kacst": ("GPL-2.0-only", 15),
      "kacst-one": ("GPL-2.0-only", 2),
      "lohit-assamese": ("OFL-1.1", 1),
      "lohit-bengali": ("OFL-1.1", 1),
      "lohit-devanagari": ("OFL-1.1", 1),
      "lohit-gujarati": ("OFL-1.1", 1),
      "lohit-kannada": ("OFL-1.1", 1),
      "lohit-malayalam": ("OFL-1.1", 1),
      "lohit-oriya": ("OFL-1.1", 1),
      "lohit-punjabi": ("OFL-1.1", 1),
      "lohit-tamil": ("OFL-1.1", 1),
      "lohit-tamil-classical": ("OFL-1.1", 1),
      "lohit-telugu": ("OFL-1.1", 1),
      "nanum": ("OFL-1.1", 8),
      "noto": ("OFL-1.1", 45),
      "openoffice": ("OFL-1.0", 1),
      "opensans": ("Apache-2.0", 5),
      "padauk": ("OFL-1.1", 4),
      "takao-gothic": ("IPA", 3),
      "ubuntu-font-family": ("UFL-1.0", 13),
      "wqy-zenhei": (
        "GPL-2.0-only WITH Font-exception-2.0", 1
      ),
    }
    for component_id, (spdx, evidence_count) in expected_component_licenses.items():
      self.assertEqual(spdx, reviewed_by_id[component_id]["spdx"])
      self.assertEqual(evidence_count, len(reviewed_by_id[component_id]["evidence"]))

    self.assertTrue(all(
      record["type"] == "font-name"
      for record in reviewed_by_id["wqy-zenhei"]["evidence"]
    ))
    for component_id in (
      "fonts-beng-extra", "fonts-gujr-extra", "kacst", "kacst-one"
    ):
      self.assertTrue(all(
        record["type"] == "repository-git-blob"
        and record["repository"] == "license-evidence"
        for record in reviewed_by_id[component_id]["evidence"]
      ))

    dictionaries = next(
      repository
      for repository in value["repositories"]
      if repository["id"] == "dictionaries"
    )
    reviewed_dictionaries = {
      component["id"]: component
      for component in dictionaries["license"]["reviewedComponents"]
    }
    expected_dictionary_licenses = {
      "ca_ES": (
        "GPL-2.0-or-later AND GPL-3.0-or-later",
        {"ca_ES/ca_ES.aff", "ca_ES/hyph_ca_ES.dic"},
        3,
      ),
      "ca_ES_valencia": (
        "GPL-2.0-or-later OR LGPL-2.1-or-later",
        {"ca_ES_valencia/ca_ES_valencia.aff"},
        2,
      ),
      "cs_CZ": ("GPL-2.0-only", {"cs_CZ/cs_CZ_Czech.txt"}, 3),
      "de_AT": (
        german_spdx,
        {"de_AT/README_de_DE_frami.txt", "de_AT/README_hyph_de.txt"},
        3,
      ),
      "de_CH": (
        german_spdx,
        {"de_CH/README_de_DE_frami.txt", "de_CH/README_hyph_de.txt"},
        3,
      ),
      "de_DE": (
        german_spdx,
        {"de_DE/README_de_DE_frami.txt", "de_DE/README_hyph_de.txt"},
        3,
      ),
      "en_CA": (
        "LicenseRef-SCOWL-2020-12-07", {"en_CA/Readme_en_CA.txt"}, 2
      ),
      "en_GB": (
        "LGPL-3.0-only AND LicenseRef-Hyphen-en-GB-2011-10-07",
        {"en_GB/README_hyph_en_GB.txt", "en_GB/lgpl-3.0.txt"},
        3,
      ),
      "en_US": (
        "LicenseRef-SCOWL-2020-12-07 AND "
        "LicenseRef-Hyphen-en-US-2011-10-07 AND WordNet",
        {
          "en_US/README_en_US.txt",
          "en_US/README_hyph_en_US.txt",
          "en_US/WordNet_license.txt",
        },
        5,
      ),
      "eu_ES": ("GPL-2.0-only", {"eu_ES/Reamde_eu_ES.txt"}, 2),
      "fr_FR": (
        "MPL-2.0 AND MIT AND LGPL-2.1-or-later",
        {"fr_FR/README_hyph_fr_FR.txt", "fr_FR/fr_FR_README.txt"},
        3,
      ),
      "gl_ES": (
        "GPL-3.0-only", {"gl_ES/GPLv3.txt", "gl_ES/README_hyph_gl_ES.txt"}, 3
      ),
      "hu_HU": (
        "GPL-2.0-or-later OR LGPL-2.1-or-later OR MPL-1.1",
        {"hu_HU/README_hu_HU.txt", "hu_HU/hyph_hu_HU.dic"},
        3,
      ),
      "ko_KR": (
        "GPL-3.0-or-later AND (GPL-2.0-or-later OR LGPL-2.1-or-later OR MPL-1.1)",
        {"ko_KR/ko_KR.aff", "ko_KR/ko_KR_LICENSE.txt"},
        2,
      ),
      "lb_LU": ("EUPL-1.1", {"lb_LU/Readme_lb_LU.txt"}, 2),
      "nl_NL": (
        "BSD-3-Clause OR CC-BY-3.0", {"nl_NL/nl_NL_Dutch.txt"}, 3
      ),
      "ro_RO": ("GPL-2.0-only", {"ro_RO/ro_RO_Romanian.txt"}, 3),
      "sr_Cyrl_RS": (
        "LGPL-3.0-only", {"sr_Cyrl_RS/Readme_sr_Cyrl_RS.txt"}, 3
      ),
      "sr_Latn_RS": (
        "LGPL-3.0-only", {"sr_Latn_RS/Readme_sr_Latn_RS.txt"}, 3
      ),
    }
    for component_id, (spdx, locators, evidence_count) in (
      expected_dictionary_licenses.items()
    ):
      component = reviewed_dictionaries[component_id]
      self.assertEqual(spdx, component["spdx"])
      self.assertEqual(evidence_count, len(component["evidence"]))
      self.assertEqual(
        locators,
        {record["locator"] for record in component["evidence"]},
      )
    self.assertEqual(
      [
        ["LicenseRef-SCOWL-2020-12-07"],
        ["LicenseRef-SCOWL-2020-12-07"],
        [],
        [],
        ["LicenseRef-Hyphen-en-US-2011-10-07"],
      ],
      [
        record["licenseRefs"]
        for record in reviewed_dictionaries["en_US"]["evidence"]
      ],
    )
    self.assertEqual(
      [[], [], ["LicenseRef-Hyphen-en-GB-2011-10-07"]],
      [
        record["licenseRefs"]
        for record in reviewed_dictionaries["en_GB"]["evidence"]
      ],
    )
    self.assertEqual(
      18, len(dictionaries["license"]["unresolvedComponents"])
    )
    for component_id in ("de_AT", "de_CH", "de_DE", "en_GB"):
      self.assertNotIn(
        component_id, dictionaries["license"]["unresolvedComponents"]
      )
      self.assertTrue(all(
        record["type"] == "repository-git-blob"
        and record["repository"] == "license-evidence"
        for record in reviewed_dictionaries[component_id]["evidence"]
      ))
    self.assertIn(
      "hu_HU/hyph_hu_HU.dic", dictionaries["license"]["patterns"]
    )
    self.assertIn("ca_ES/ca_ES.aff", dictionaries["license"]["patterns"])
    self.assertIn("ko_KR/ko_KR.aff", dictionaries["license"]["patterns"])
    for component_id in ("kk_KZ", "pt_BR"):
      self.assertNotIn(component_id, reviewed_dictionaries)
      self.assertIn(
        component_id, dictionaries["license"]["unresolvedComponents"]
      )
    blocking_reviews = {
      review["id"]: review
      for review in dictionaries["license"]["blockingReviews"]
    }
    expected_blocking_reviews = {
      "da_DK": ("AMBIGUOUS_VERSION", ["da_DK/README_hyph_da_DK.txt"]),
      "el_GR": ("AMBIGUOUS_VERSION", ["el_GR/README_hyph_el_GR.txt"]),
      "en_AU": ("MISSING_EVIDENCE", ["en_AU/README_en_AU.txt"]),
      "hr_HR": ("AMBIGUOUS_VERSION", ["hr_HR/README_hyph_hr_HR.txt"]),
      "id_ID": ("MISSING_EVIDENCE", ["id_ID/README_id_ID.txt"]),
      "it_IT": ("AMBIGUOUS_VERSION", ["it_IT/README_hyph_it_IT.txt"]),
      "kk_KZ": ("AMBIGUOUS_CHOICE", ["kk_KZ/README_kk_KZ.txt"]),
      "lt_LT": ("MISSING_EVIDENCE", ["lt_LT/lt_LT_Lithuanian.txt"]),
      "mn_MN": ("CONFLICTING_TERMS", ["mn_MN/Readme_mn_MN.txt"]),
      "pl_PL": ("AMBIGUOUS_VERSION", ["pl_PL/pl_PL_Polish.txt"]),
      "pt_BR": ("AMBIGUOUS_VERSION", ["pt_BR/README_hyph_pt_BR.txt"]),
      "pt_PT": (
        "CONFLICTING_TERMS",
        [
          "pt_PT/LICENSES.txt",
          "pt_PT/README_hyph_pt_PT.txt",
          "pt_PT/README_pt_PT.txt",
        ],
      ),
      "sl_SI": ("AMBIGUOUS_VERSION", ["sl_SI/README_hyph_sl_SI.txt"]),
      "uk_UA": ("AMBIGUOUS_VERSION", ["uk_UA/README_th_uk_UA.txt"]),
      "uz_Cyrl_UZ": ("MISSING_EVIDENCE", ["uz_Cyrl_UZ/README.md"]),
      "uz_Latn_UZ": ("MISSING_EVIDENCE", ["uz_Latn_UZ/README.md"]),
    }
    self.assertEqual(sorted(expected_blocking_reviews), sorted(blocking_reviews))
    for component_id, (code, evidence_paths) in expected_blocking_reviews.items():
      self.assertEqual(code, blocking_reviews[component_id]["code"])
      self.assertEqual(
        evidence_paths,
        [
          record["path"]
          for record in blocking_reviews[component_id]["evidence"]
        ],
      )
    expected_lgpl_evidence = {
      "bg_BG": "bg_BG/Readme_bg_BG.txt",
      "en_ZA": "en_ZA/Readme_en_ZA.txt",
    }
    for component_id, locator in expected_lgpl_evidence.items():
      component = reviewed_dictionaries[component_id]
      self.assertEqual("LGPL-2.1-only", component["spdx"])
      self.assertEqual(
        {locator},
        {record["locator"] for record in component["evidence"]},
      )
      self.assertTrue(all(
        record["path"].startswith(component_id + "/")
        for record in component["evidence"]
      ))

  def test_incomplete_license_inventory_requires_precise_sorted_components(self):
    value = source_inputs()
    value["repositories"][1]["license"] = {
      "status": "component-scoped",
      "payloadPatterns": ["**/*.ttf"],
      "patterns": ["**/LICENSE*"],
      "reason": "A reviewed mapping is incomplete.",
      "unresolvedComponents": ["missing-font"],
    }
    validate_inputs(value)
    finding = policy_findings(value)[0]
    self.assertEqual(["missing-font"], finding["unresolvedComponents"])

    value["repositories"][1]["license"]["unresolvedComponents"] = [
      "missing-font", "missing-font",
    ]
    with self.assertRaisesRegex(ResolutionError, "sorted unique strings"):
      validate_inputs(value)

  def test_reviewed_component_evidence_is_strict_and_disjoint_from_unresolved(self):
    value = source_inputs()
    value["repositories"][1]["license"] = {
      "status": "component-scoped",
      "payloadPatterns": ["**/*.ttf"],
      "patterns": ["**/LICENSE*"],
      "reason": "Some component evidence is still missing.",
      "reviewedComponents": [
        {
          "id": "licensed-font",
          "spdx": "GPL-3.0-or-later WITH Font-exception-2.0",
          "evidence": [
            {
              "type": "font-name",
              "path": "licensed-font/font.ttf",
              "locator": "name:13",
              "sha256": "a" * 64,
            }
          ],
        }
      ],
      "unresolvedComponents": ["missing-font"],
    }
    validate_inputs(value)

    value["repositories"][1]["license"]["unresolvedComponents"] = [
      "licensed-font",
      "missing-font",
    ]
    with self.assertRaisesRegex(ResolutionError, "both reviewed and unresolved"):
      validate_inputs(value)

    value["repositories"][1]["license"]["unresolvedComponents"] = ["missing-font"]
    value["repositories"][1]["license"]["reviewedComponents"][0]["spdx"] = (
      "NOASSERTION"
    )
    with self.assertRaisesRegex(ResolutionError, "reviewed source set"):
      validate_inputs(value)

    value["repositories"][1]["license"]["reviewedComponents"][0]["spdx"] = (
      "GPL-3.0-or-later WITH Font-exception-2.0"
    )
    value["repositories"][1]["license"]["unresolvedComponents"] = ["z", "a"]
    with self.assertRaisesRegex(ResolutionError, "sorted unique strings"):
      validate_inputs(value)

  def test_multiple_custom_licenses_require_explicit_evidence_bindings(self):
    value = json.loads(
      (REPOSITORY_ROOT / "locks" / "source-inputs.v1.json").read_text(
        encoding="utf-8"
      )
    )
    dictionaries = next(
      repository for repository in value["repositories"]
      if repository["id"] == "dictionaries"
    )
    en_us = next(
      component for component in dictionaries["license"]["reviewedComponents"]
      if component["id"] == "en_US"
    )

    del en_us["evidence"][0]["licenseRefs"]
    with self.assertRaisesRegex(ResolutionError, "required when an expression has multiple"):
      validate_inputs(value)

    value = json.loads(
      (REPOSITORY_ROOT / "locks" / "source-inputs.v1.json").read_text(
        encoding="utf-8"
      )
    )
    dictionaries = next(
      repository for repository in value["repositories"]
      if repository["id"] == "dictionaries"
    )
    en_us = next(
      component for component in dictionaries["license"]["reviewedComponents"]
      if component["id"] == "en_US"
    )
    en_us["evidence"][-1]["licenseRefs"] = []
    with self.assertRaisesRegex(ResolutionError, "every LicenseRef identifier needs evidence"):
      validate_inputs(value)

  def test_multiple_custom_license_bindings_survive_inventory_and_source_lock(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      component = checkout / "dictionary"
      component.mkdir()
      payloads = {
        "hyphen.bin": b"hyphen payload\n",
        "scowl.bin": b"scowl payload\n",
        "thesaurus.bin": b"wordnet payload\n",
      }
      license_texts = {
        "hyphen.txt": b"hyphen terms\n",
        "SCOWL.txt": b"SCOWL terms\n",
        "WordNet.txt": b"WordNet terms\n",
      }
      for name, content in {**payloads, **license_texts}.items():
        (component / name).write_bytes(content)
      run_git(checkout, "add", "dictionary")
      run_git(checkout, "commit", "-m", "add compound-license fixture")
      commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
      bare = Path(directory) / "inventory.git"
      run_git(directory, "clone", "--bare", str(checkout), str(bare))

      scowl_ref = "LicenseRef-SCOWL-2020-12-07"
      hyphen_ref = "LicenseRef-Hyphen-en-US-2011-10-07"
      repository = repository_input("dictionaries", commit)
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.bin"],
        "patterns": ["**/*.txt"],
        "reason": "All compound-license evidence has been reviewed.",
        "reviewedComponents": [{
          "id": "dictionary",
          "spdx": f"{scowl_ref} AND {hyphen_ref} AND WordNet",
          "evidence": [
            {
              "type": "git-blob",
              "path": "dictionary/hyphen.bin",
              "locator": "dictionary/hyphen.txt",
              "licenseRefs": [hyphen_ref],
              "sha256": hashlib.sha256(license_texts["hyphen.txt"]).hexdigest(),
            },
            {
              "type": "git-blob",
              "path": "dictionary/scowl.bin",
              "locator": "dictionary/SCOWL.txt",
              "licenseRefs": [scowl_ref],
              "sha256": hashlib.sha256(license_texts["SCOWL.txt"]).hexdigest(),
            },
            {
              "type": "git-blob",
              "path": "dictionary/thesaurus.bin",
              "locator": "dictionary/WordNet.txt",
              "licenseRefs": [],
              "sha256": hashlib.sha256(license_texts["WordNet.txt"]).hexdigest(),
            },
          ],
        }],
        "unresolvedComponents": [],
      }

      inventory = repository_license_inventory(repository, bare, commit)
      expected_bindings = [[hyphen_ref], [scowl_ref], []]
      self.assertEqual(
        expected_bindings,
        [
          evidence["licenseRefs"]
          for evidence in inventory["components"][0]["license"]["evidence"]
        ],
      )
      validate_contract(
        {
          "schemaVersion": 1,
          "auditType": "source-license-inventory",
          "productVersion": "9.4.0",
          "status": "passed",
          "repositories": [inventory],
        },
        "source-license-audit",
        REPOSITORY_ROOT / "schemas",
      )

      record = repository_metadata(repository, bare, commit)
      self.assertEqual(
        expected_bindings,
        [
          evidence["licenseRefs"]
          for evidence in record["license"]["components"][0]["license"]["evidence"]
        ],
      )
      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": {"repository": "dictionaries", "commit": commit},
        "sourceDateEpoch": record["commitTime"],
        "repositories": [record],
        "relationships": [],
      }
      bind_source_tree_manifest(lock, {"dictionaries": bare})
      validate_contract(lock, "source-lock", REPOSITORY_ROOT / "schemas")

  def test_blocking_license_reviews_are_locked_and_stay_unresolved(self):
    value = source_inputs()
    value["repositories"][1]["license"] = {
      "status": "component-scoped",
      "payloadPatterns": ["**/*.ttf"],
      "patterns": ["**/LICENSE*"],
      "reason": "A component has conflicting license terms.",
      "blockingReviews": [
        {
          "id": "blocked-font",
          "code": "CONFLICTING_TERMS",
          "reason": "The locked notice grants and prohibits redistribution.",
          "evidence": [
            {
              "path": "blocked-font/LICENSE.txt",
              "sha256": "a" * 64,
            }
          ],
        }
      ],
      "unresolvedComponents": ["blocked-font"],
    }
    validate_inputs(value)

    value["repositories"][1]["license"]["unresolvedComponents"] = []
    with self.assertRaisesRegex(ResolutionError, "blocking review.*unresolved"):
      validate_inputs(value)

    value["repositories"][1]["license"]["unresolvedComponents"] = [
      "blocked-font"
    ]
    value["repositories"][1]["license"]["blockingReviews"][0]["code"] = (
      "UNREVIEWED"
    )
    with self.assertRaisesRegex(ResolutionError, "unsupported review code"):
      validate_inputs(value)

  def test_blocking_license_review_is_verified_from_locked_git_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      license_bytes = b"Conflicting license terms\n"
      (checkout / "blocked").mkdir()
      (checkout / "blocked" / "Font.ttf").write_bytes(b"font\n")
      (checkout / "blocked" / "LICENSE.txt").write_bytes(license_bytes)
      run_git(checkout, "add", "blocked")
      run_git(checkout, "commit", "-m", "add blocked component")
      commit = run_git(checkout, "rev-parse", "HEAD")
      bare = Path(directory) / "inventory.git"
      run_git(directory, "clone", "--bare", str(checkout), str(bare))
      repository = repository_input("fonts", commit)
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.ttf"],
        "patterns": ["**/LICENSE*"],
        "reason": "A component has conflicting license terms.",
        "blockingReviews": [
          {
            "id": "blocked",
            "code": "CONFLICTING_TERMS",
            "reason": "The locked notice contains conflicting terms.",
            "evidence": [
              {
                "path": "blocked/LICENSE.txt",
                "sha256": hashlib.sha256(license_bytes).hexdigest(),
              }
            ],
          }
        ],
        "unresolvedComponents": ["blocked"],
      }

      inventory = repository_license_inventory(repository, bare, commit)

      component = inventory["components"][0]
      self.assertEqual("blocked", component["status"])
      self.assertEqual(
        "CONFLICTING_TERMS", component["blockingReview"]["code"]
      )
      self.assertEqual(
        hashlib.sha256(license_bytes).hexdigest(),
        component["blockingReview"]["evidence"][0]["sha256"],
      )

      repository["license"]["blockingReviews"][0]["evidence"][0][
        "sha256"
      ] = "0" * 64
      with self.assertRaisesRegex(ResolutionError, "blocking review digest"):
        repository_license_inventory(repository, bare, commit)

  def test_component_license_inventory_is_derived_from_locked_git_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      (checkout / "licensed").mkdir()
      (checkout / "licensed" / "Font.ttf").write_bytes(b"font one\n")
      (checkout / "licensed" / "LICENSE.txt").write_text(
        "font license\n",
        encoding="utf-8",
        newline="\n",
      )
      (checkout / "missing").mkdir()
      (checkout / "missing" / "Font.ttf").write_bytes(b"font two\n")
      run_git(checkout, "add", "licensed", "missing")
      run_git(checkout, "commit", "-m", "add component payloads")
      commit = run_git(checkout, "rev-parse", "HEAD")
      bare = Path(directory) / "inventory.git"
      run_git(directory, "clone", "--bare", str(checkout), str(bare))
      repository = repository_input("fonts", commit)
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.ttf"],
        "patterns": ["**/LICENSE*"],
        "reason": "A component license mapping is incomplete.",
        "unresolvedComponents": ["licensed", "missing"],
      }

      inventory = repository_license_inventory(repository, bare, commit)

      self.assertEqual("incomplete", inventory["status"])
      self.assertEqual(
        ["licensed", "missing"],
        [component["id"] for component in inventory["components"]],
      )
      licensed = inventory["components"][0]
      self.assertEqual("review-required", licensed["status"])
      self.assertEqual(
        hashlib.sha256(b"font license\n").hexdigest(),
        licensed["candidateEvidence"][0]["sha256"],
      )
      repository["license"]["unresolvedComponents"] = ["licensed"]
      with self.assertRaisesRegex(ResolutionError, "inventory is stale"):
        repository_license_inventory(repository, bare, commit)

  def test_reviewed_component_evidence_is_verified_from_locked_payload_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      license_text = "GNU font license with exception"
      font_bytes = font_with_license_name(license_text)
      (checkout / "font-family").mkdir()
      (checkout / "font-family" / "Font.ttf").write_bytes(font_bytes)
      archive_license = b"GLEW license terms\n"
      (checkout / "glew").mkdir()
      with zipfile.ZipFile(checkout / "glew" / "glew.zip", "w") as archive:
        archive.writestr("glew/LICENSE.txt", archive_license)
      (checkout / "missing").mkdir()
      (checkout / "missing" / "Font.ttf").write_bytes(b"not a font")
      run_git(checkout, "add", "font-family", "glew", "missing")
      run_git(checkout, "commit", "-m", "add component payloads")
      commit = run_git(checkout, "rev-parse", "HEAD")
      bare = Path(directory) / "inventory.git"
      run_git(directory, "clone", "--bare", str(checkout), str(bare))
      repository = repository_input("components", commit)
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.ttf", "**/*.zip"],
        "patterns": ["**/LICENSE*"],
        "reason": "One component has no reviewed evidence.",
        "reviewedComponents": [
          {
            "id": "font-family",
            "spdx": "GPL-3.0-or-later WITH Font-exception-2.0",
            "evidence": [
              {
                "type": "font-name",
                "path": "font-family/Font.ttf",
                "locator": "name:13",
                "sha256": hashlib.sha256(license_text.encode("utf-8")).hexdigest(),
              }
            ],
          },
          {
            "id": "glew",
            "spdx": "BSD-3-Clause AND MIT",
            "evidence": [
              {
                "type": "zip-member",
                "path": "glew/glew.zip",
                "locator": "glew/LICENSE.txt",
                "sha256": hashlib.sha256(archive_license).hexdigest(),
              }
            ],
          },
        ],
        "unresolvedComponents": ["missing"],
      }

      inventory = repository_license_inventory(repository, bare, commit)

      self.assertEqual(
        ["font-family", "glew", "missing"],
        [component["id"] for component in inventory["components"]],
      )
      for component in inventory["components"][:2]:
        self.assertEqual("resolved", component["status"])
        self.assertEqual([], component["candidateEvidence"])
        self.assertEqual(
          component["payloadPaths"],
          [record["path"] for record in component["license"]["evidence"]],
        )
      self.assertEqual("unresolved", inventory["components"][2]["status"])

      repository["license"]["reviewedComponents"][0]["evidence"][0]["sha256"] = (
        "0" * 64
      )
      with self.assertRaisesRegex(ResolutionError, "license evidence digest"):
        repository_license_inventory(repository, bare, commit)

  def test_reviewed_component_evidence_maps_locked_git_blob_to_payloads(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      license_bytes = b"Permission is hereby granted, free of charge.\n"
      other_license_bytes = b"This license belongs to another component.\n"
      (checkout / "dictionary").mkdir()
      (checkout / "dictionary" / "dictionary.aff").write_bytes(b"SET UTF-8\n")
      (checkout / "dictionary" / "dictionary.dic").write_bytes(b"1\nword\n")
      (checkout / "dictionary" / "LICENSE.txt").write_bytes(license_bytes)
      (checkout / "other").mkdir()
      (checkout / "other" / "LICENSE.txt").write_bytes(other_license_bytes)
      run_git(checkout, "add", "dictionary", "other")
      run_git(checkout, "commit", "-m", "add dictionary payloads")
      commit = run_git(checkout, "rev-parse", "HEAD")
      bare = Path(directory) / "inventory.git"
      run_git(directory, "clone", "--bare", str(checkout), str(bare))
      repository = repository_input("dictionaries", commit)
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.aff", "**/*.dic"],
        "patterns": ["**/LICENSE*"],
        "reason": "The dictionary license mapping was reviewed.",
        "reviewedComponents": [
          {
            "id": "dictionary",
            "spdx": "MIT",
            "evidence": [
              {
                "type": "git-blob",
                "path": payload_path,
                "locator": "dictionary/LICENSE.txt",
                "sha256": hashlib.sha256(license_bytes).hexdigest(),
              }
              for payload_path in [
                "dictionary/dictionary.aff",
                "dictionary/dictionary.dic",
              ]
            ],
          }
        ],
        "unresolvedComponents": [],
      }

      inputs = source_inputs()
      inputs["repositories"][1]["commit"] = commit
      inputs["repositories"][1]["license"] = repository["license"]
      inputs["baseline"]["commit"] = commit
      validate_inputs(inputs)
      inventory = repository_license_inventory(repository, bare, commit)

      component = inventory["components"][0]
      self.assertEqual("resolved", component["status"])
      self.assertEqual(
        ["dictionary/dictionary.aff", "dictionary/dictionary.dic"],
        [record["path"] for record in component["license"]["evidence"]],
      )
      self.assertTrue(all(
        record["locator"] == "dictionary/LICENSE.txt"
        for record in component["license"]["evidence"]
      ))

      repository["license"]["reviewedComponents"][0]["evidence"][0][
        "sha256"
      ] = "0" * 64
      with self.assertRaisesRegex(ResolutionError, "license evidence digest"):
        repository_license_inventory(repository, bare, commit)

      evidence = repository["license"]["reviewedComponents"][0]["evidence"][0]
      evidence["locator"] = "other/LICENSE.txt"
      evidence["sha256"] = hashlib.sha256(other_license_bytes).hexdigest()
      with self.assertRaisesRegex(ResolutionError, "component license candidate"):
        repository_license_inventory(repository, bare, commit)

      evidence["locator"] = "dictionary"
      evidence["sha256"] = hashlib.sha256(license_bytes).hexdigest()
      with self.assertRaisesRegex(ResolutionError, "expected locked git blob"):
        repository_license_inventory(repository, bare, commit)

  def test_repository_license_evidence_audit_uses_locked_mirror_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      inputs, caches, payload, _ = create_repository_evidence_fixture(directory)
      validate_inputs(inputs)
      cache_root = Path(directory) / "cache"
      cache_git = cache_root / "git"
      cache_git.mkdir(parents=True)
      for repository_id in ["font-source", "license-evidence"]:
        caches[repository_id].rename(cache_git / (repository_id + ".git"))

      report = license_inventory_report(inputs, cache_root)
      validate_contract(report, "source-license-audit", REPOSITORY_ROOT / "schemas")
      source_record = next(
        item for item in report["repositories"]
        if item["repository"] == "font-source"
      )
      locked = source_record["components"][0]["license"]["evidence"][0]
      self.assertEqual("repository-git-blob", locked["type"])
      self.assertEqual(
        hashlib.sha256(payload).hexdigest(),
        locked["referenceSha256"],
      )

      source = next(
        item for item in inputs["repositories"] if item["id"] == "font-source"
      )
      source["license"]["reviewedComponents"][0]["evidence"][0][
        "referencePath"
      ] = "fonts/Mismatch.ttf"
      validate_inputs(inputs)
      with self.assertRaisesRegex(ResolutionError, "referenced payload bytes"):
        license_inventory_report(inputs, cache_root)

  def test_repository_license_evidence_policy_fails_closed(self):
    with tempfile.TemporaryDirectory() as directory:
      inputs, _, _, _ = create_repository_evidence_fixture(directory)
      validate_inputs(inputs)

      missing = json.loads(json.dumps(inputs))
      missing["repositories"] = [
        item for item in missing["repositories"]
        if item["id"] != "license-evidence"
      ]
      with self.assertRaisesRegex(ResolutionError, "not selected"):
        validate_inputs(missing)

      inactive = json.loads(json.dumps(inputs))
      inactive_reference = next(
        item for item in inactive["repositories"]
        if item["id"] == "license-evidence"
      )
      inactive_reference["active"] = False
      inactive_reference["buildInput"] = False
      with self.assertRaisesRegex(ResolutionError, "active build input"):
        validate_inputs(inactive)

      non_build = json.loads(json.dumps(inputs))
      next(
        item for item in non_build["repositories"]
        if item["id"] == "license-evidence"
      )["buildInput"] = False
      with self.assertRaisesRegex(ResolutionError, "active build input"):
        validate_inputs(non_build)

      mutable_selection = json.loads(json.dumps(inputs))
      mutable_reference = next(
        item for item in mutable_selection["repositories"]
        if item["id"] == "license-evidence"
      )
      mutable_reference["projectFork"] = True
      mutable_reference["selection"] = {
        "type": "branch",
        "ref": "refs/heads/develop",
      }
      with self.assertRaisesRegex(ResolutionError, "immutable tag"):
        validate_inputs(mutable_selection)

      spdx_drift = json.loads(json.dumps(inputs))
      next(
        item for item in spdx_drift["repositories"]
        if item["id"] == "license-evidence"
      )["license"]["reviewedComponents"][0]["spdx"] = "MIT"
      with self.assertRaisesRegex(ResolutionError, "SPDX expressions"):
        validate_inputs(spdx_drift)

      mapping_drift = json.loads(json.dumps(inputs))
      next(
        item for item in mapping_drift["repositories"]
        if item["id"] == "font-source"
      )["license"]["reviewedComponents"][0]["evidence"][0][
        "locator"
      ] = "fonts/OTHER-LICENSE.txt"
      with self.assertRaisesRegex(ResolutionError, "not mapped"):
        validate_inputs(mapping_drift)

  def test_repository_license_evidence_survives_lock_revalidation_and_materialize(self):
    with tempfile.TemporaryDirectory() as directory:
      inputs, caches, payload, license_text = create_repository_evidence_fixture(
        directory
      )
      validate_inputs(inputs)
      commits = {
        repository["id"]: repository.get("commit")
        or run_git(caches[repository["id"]], "rev-parse", "HEAD^{commit}")
        for repository in inputs["repositories"]
      }
      contexts = {
        repository["id"]: {
          "repository": repository,
          "cache": caches[repository["id"]],
          "commit": commits[repository["id"]],
          "lfsObjects": [],
        }
        for repository in inputs["repositories"]
      }
      records = [
        repository_metadata(
          repository,
          caches[repository["id"]],
          commits[repository["id"]],
          contexts,
        )
        for repository in inputs["repositories"]
      ]
      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": dict(inputs["baseline"]),
        "sourceDateEpoch": max(item["commitTime"] for item in records),
        "repositories": records,
        "relationships": [],
      }
      bind_source_tree_manifest(lock, caches)
      validate_contract(lock, "source-lock", REPOSITORY_ROOT / "schemas")

      source_repository = next(
        item for item in lock["repositories"] if item["id"] == "font-source"
      )
      evidence = source_repository["license"]["components"][0]["license"][
        "evidence"
      ][0]
      self.assertEqual(hashlib.sha256(payload).hexdigest(), evidence["sha256"])
      self.assertEqual(evidence["sha256"], evidence["referenceSha256"])
      self.assertEqual(
        hashlib.sha256(license_text).hexdigest(), evidence["evidenceSha256"]
      )

      with patch(
        "source_resolver.sync_cache",
        side_effect=lambda repository, _cache, _commit: caches[repository["id"]],
      ):
        self.assertEqual(
          caches,
          caches_from_lock(lock, Path(directory) / "revalidation-cache"),
        )

      source_root = Path(directory) / "materialized"
      materialize(lock, caches, source_root)
      verify_materialized(lock, source_root)

      payload_digest_drift = json.loads(json.dumps(lock))
      next(
        item for item in payload_digest_drift["repositories"]
        if item["id"] == "font-source"
      )["license"]["components"][0]["license"]["evidence"][0][
        "sha256"
      ] = "0" * 64
      with self.assertRaisesRegex(ResolutionError, "payload digest"):
        verify_materialized(payload_digest_drift, source_root)

      reference_digest_drift = json.loads(json.dumps(lock))
      next(
        item for item in reference_digest_drift["repositories"]
        if item["id"] == "font-source"
      )["license"]["components"][0]["license"]["evidence"][0][
        "referenceSha256"
      ] = "0" * 64
      with self.assertRaisesRegex(ResolutionError, "referenced payload digest"):
        verify_materialized(reference_digest_drift, source_root)

      reference_blob_drift = json.loads(json.dumps(lock))
      source_evidence = next(
        item for item in reference_blob_drift["repositories"]
        if item["id"] == "font-source"
      )["license"]["components"][0]["license"]["evidence"][0]
      reference_evidence = next(
        item for item in reference_blob_drift["repositories"]
        if item["id"] == "license-evidence"
      )["license"]["components"][0]["license"]["evidence"][0]
      source_evidence["referenceBlob"] = "0" * 40
      reference_evidence["blob"] = "0" * 40
      with self.assertRaisesRegex(ResolutionError, "referenced payload blob"):
        verify_materialized(reference_blob_drift, source_root)

      license_blob_drift = json.loads(json.dumps(lock))
      next(
        item for item in license_blob_drift["repositories"]
        if item["id"] == "font-source"
      )["license"]["components"][0]["license"]["evidence"][0][
        "evidenceBlob"
      ] = "0" * 40
      with self.assertRaisesRegex(ResolutionError, "license evidence blob"):
        verify_materialized(license_blob_drift, source_root)

      license_digest_drift = json.loads(json.dumps(lock))
      source_evidence = next(
        item for item in license_digest_drift["repositories"]
        if item["id"] == "font-source"
      )["license"]["components"][0]["license"]["evidence"][0]
      reference_evidence = next(
        item for item in license_digest_drift["repositories"]
        if item["id"] == "license-evidence"
      )["license"]["components"][0]["license"]["evidence"][0]
      source_evidence["evidenceSha256"] = "0" * 64
      reference_evidence["evidenceSha256"] = "0" * 64
      with self.assertRaisesRegex(ResolutionError, "license evidence digest"):
        verify_materialized(license_digest_drift, source_root)

  def test_license_audit_reads_the_standard_git_cache_layout(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, bare, _ = create_repository(directory)
      (checkout / "missing.ttf").write_bytes(b"font\n")
      run_git(checkout, "add", "missing.ttf")
      run_git(checkout, "commit", "-m", "add unlicensed font")
      commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
      run_git(bare, "fetch", str(checkout), f"{commit}:refs/heads/main")
      repository = repository_input("source", commit)
      repository["license"] = {
        "status": "missing",
        "payloadPatterns": ["**/*.ttf"],
        "reason": "The component has no reviewed license evidence.",
        "unresolvedComponents": ["missing.ttf"],
      }
      run_git(bare, "remote", "set-url", "origin", repository["origin"])
      cache_root = Path(directory) / "cache"
      cache = cache_root / "git" / "source.git"
      cache.parent.mkdir(parents=True)
      bare.rename(cache)

      report = license_inventory_report(
        {"productVersion": "9.4.0", "repositories": [repository]},
        cache_root,
      )

      self.assertEqual("source", report["repositories"][0]["repository"])

  def test_license_audit_reports_every_component_without_reviewed_evidence(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, bare, _ = create_repository(directory)
      (checkout / "candidate").mkdir()
      (checkout / "candidate" / "Font.ttf").write_bytes(b"candidate font\n")
      (checkout / "candidate" / "LICENSE.txt").write_text(
        "candidate license\n",
        encoding="utf-8",
        newline="\n",
      )
      (checkout / "missing").mkdir()
      (checkout / "missing" / "Font.ttf").write_bytes(b"missing font\n")
      run_git(checkout, "add", "candidate", "missing")
      run_git(checkout, "commit", "-m", "add incomplete license inventory")
      commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
      run_git(bare, "fetch", str(checkout), f"{commit}:refs/heads/main")

      inputs = source_inputs()
      repository = inputs["repositories"][1]
      repository["commit"] = commit
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.ttf"],
        "patterns": ["**/LICENSE*"],
        "reason": "Two components still need review.",
        "unresolvedComponents": ["candidate", "missing"],
      }
      inputs["baseline"]["commit"] = commit
      run_git(bare, "remote", "set-url", "origin", repository["origin"])
      cache_root = Path(directory) / "cache"
      cache = cache_root / "git" / "documentserver.git"
      cache.parent.mkdir(parents=True)
      bare.rename(cache)
      inputs_path = Path(directory) / "inputs.json"
      report_path = Path(directory) / "source-license-audit.json"
      inputs_path.write_text(json.dumps(inputs), encoding="utf-8")

      with patch("sys.stderr", new_callable=io.StringIO) as stderr:
        exit_code = main([
          "license-audit",
          "--inputs", str(inputs_path),
          "--cache-directory", str(cache_root),
          "--report", str(report_path),
          "--schema-dir", str(REPOSITORY_ROOT / "schemas"),
        ])

      report = json.loads(report_path.read_text(encoding="utf-8"))
      self.assertEqual(3, exit_code)
      self.assertEqual("failed", report["status"])
      self.assertEqual("incomplete", report["repositories"][0]["status"])
      self.assertIn("candidate, missing", stderr.getvalue())

  def test_license_audit_passes_when_every_component_has_reviewed_evidence(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, bare, _ = create_repository(directory)
      license_text = "GNU font license with exception"
      (checkout / "licensed").mkdir()
      (checkout / "licensed" / "Font.ttf").write_bytes(
        font_with_license_name(license_text)
      )
      run_git(checkout, "add", "licensed")
      run_git(checkout, "commit", "-m", "add reviewed license inventory")
      commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
      run_git(bare, "fetch", str(checkout), f"{commit}:refs/heads/main")

      inputs = source_inputs()
      repository = inputs["repositories"][1]
      repository["commit"] = commit
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.ttf"],
        "patterns": ["**/LICENSE*"],
        "reason": "All component evidence has been reviewed.",
        "reviewedComponents": [
          {
            "id": "licensed",
            "spdx": "GPL-3.0-or-later WITH Font-exception-2.0",
            "evidence": [
              {
                "type": "font-name",
                "path": "licensed/Font.ttf",
                "locator": "name:13",
                "sha256": hashlib.sha256(license_text.encode("utf-8")).hexdigest(),
              }
            ],
          }
        ],
        "unresolvedComponents": [],
      }
      inputs["baseline"]["commit"] = commit
      run_git(bare, "remote", "set-url", "origin", repository["origin"])
      cache_root = Path(directory) / "cache"
      cache = cache_root / "git" / "documentserver.git"
      cache.parent.mkdir(parents=True)
      bare.rename(cache)
      inputs_path = Path(directory) / "inputs.json"
      report_path = Path(directory) / "source-license-audit.json"
      inputs_path.write_text(json.dumps(inputs), encoding="utf-8")

      with patch("sys.stderr", new_callable=io.StringIO) as stderr:
        exit_code = main([
          "license-audit",
          "--inputs", str(inputs_path),
          "--cache-directory", str(cache_root),
          "--report", str(report_path),
          "--schema-dir", str(REPOSITORY_ROOT / "schemas"),
        ])

      self.assertEqual(0, exit_code)
      self.assertEqual("", stderr.getvalue())
      report = json.loads(report_path.read_text(encoding="utf-8"))
      self.assertEqual("passed", report["status"])
      self.assertEqual("complete", report["repositories"][0]["status"])

  def test_repository_metadata_uses_git_objects_and_license_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      _, bare, commit = create_repository(directory)
      repository = repository_input("source", commit)
      record = repository_metadata(repository, bare, commit)
      self.assertEqual(commit, record["commit"])
      self.assertEqual(run_git(bare, "rev-parse", commit + "^{tree}"), record["tree"])
      self.assertEqual(
        hashlib.sha256(b"test license\n").hexdigest(),
        record["license"]["sha256"],
      )
      self.assertEqual([], record["lfsObjects"])

  def test_repository_metadata_records_complete_component_scoped_licenses(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      payload = b"licensed payload\n"
      license_text = b"complete custom license terms\n"
      (checkout / "fonts").mkdir()
      (checkout / "fonts" / "Example.ttf").write_bytes(payload)
      (checkout / "fonts" / "LICENSE.txt").write_bytes(license_text)
      run_git(checkout, "add", "fonts")
      run_git(checkout, "commit", "-m", "add component license fixture")
      commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
      bare = Path(directory) / "source-final.git"
      run_git(directory, "clone", "--bare", str(checkout), str(bare))
      repository = repository_input("source", commit)
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.ttf"],
        "patterns": ["**/LICENSE*"],
        "reason": "All component evidence has been reviewed.",
        "reviewedComponents": [{
          "id": "fonts",
          "spdx": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
          "evidence": [{
            "type": "git-blob",
            "path": "fonts/Example.ttf",
            "locator": "fonts/LICENSE.txt",
            "sha256": hashlib.sha256(license_text).hexdigest(),
          }],
        }],
        "unresolvedComponents": [],
      }

      self.assertEqual([], policy_findings({"repositories": [repository]}))
      record = repository_metadata(repository, bare, commit)
      self.assertEqual({
        "scope": "component",
        "payloadPatterns": ["**/*.ttf"],
        "components": [{
          "id": "fonts",
          "payloadPaths": ["fonts/Example.ttf"],
          "license": {
            "spdx": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
            "evidence": [{
              "type": "git-blob",
              "path": "fonts/Example.ttf",
              "blob": run_git(bare, "rev-parse", f"{commit}:fonts/Example.ttf"),
              "sha256": hashlib.sha256(payload).hexdigest(),
              "locator": "fonts/LICENSE.txt",
              "evidenceBlob": run_git(
                bare, "rev-parse", f"{commit}:fonts/LICENSE.txt"
              ),
              "evidenceSha256": hashlib.sha256(license_text).hexdigest(),
            }],
          },
        }],
      }, record["license"])
      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": {"repository": "source", "commit": commit},
        "sourceDateEpoch": record["commitTime"],
        "repositories": [record],
        "relationships": [],
      }
      bind_source_tree_manifest(lock, {"source": bare})
      validate_contract(lock, "source-lock", REPOSITORY_ROOT / "schemas")
      source_root = Path(directory) / "workspace"
      materialize(lock, {"source": bare}, source_root)
      verify_materialized(lock, source_root)

      tampered = json.loads(json.dumps(lock))
      tampered["repositories"][0]["license"]["components"][0]["license"] \
        ["evidence"][0]["evidenceSha256"] = "0" * 64
      with self.assertRaisesRegex(ResolutionError, "license evidence digest"):
        verify_materialized(tampered, source_root)

      tampered = json.loads(json.dumps(lock))
      tampered["repositories"][0]["license"]["components"][0]["license"] \
        ["evidence"][0]["evidenceBlob"] = "0" * 40
      with self.assertRaisesRegex(ResolutionError, "license evidence blob"):
        with patch(
          "source_resolver.sync_cache",
          side_effect=lambda repository, _cache, _commit: {"source": bare}[
            repository["id"]
          ],
        ):
          caches_from_lock(tampered, Path(directory) / "tampered-cache")

  def test_component_scoped_zip_evidence_uses_materialized_lfs_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      archive_stream = io.BytesIO()
      license_text = b"license stored inside an LFS archive\n"
      with zipfile.ZipFile(archive_stream, "w") as archive:
        archive.writestr("LICENSE.txt", license_text)
      (checkout / "fonts").mkdir()
      bare, commit, oid, content = add_lfs_object(
        directory,
        checkout,
        name="fonts/archive.bin",
        content=archive_stream.getvalue(),
      )
      repository = repository_input("source", commit)
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.bin"],
        "patterns": [],
        "reason": "All component evidence has been reviewed.",
        "reviewedComponents": [{
          "id": "fonts",
          "spdx": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
          "evidence": [{
            "type": "zip-member",
            "path": "fonts/archive.bin",
            "locator": "LICENSE.txt",
            "sha256": hashlib.sha256(license_text).hexdigest(),
          }],
        }],
        "unresolvedComponents": [],
      }

      record = repository_metadata(repository, bare, commit)

      evidence = record["license"]["components"][0]["license"]["evidence"][0]
      pointer = (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{oid}\n"
        f"size {len(content)}\n"
      ).encode("ascii")
      self.assertEqual(hashlib.sha256(pointer).hexdigest(), evidence["sha256"])
      self.assertEqual(oid, record["lfsObjects"][0]["oid"])
      self.assertEqual(len(content), record["lfsObjects"][0]["size"])
      self.assertEqual(hashlib.sha256(license_text).hexdigest(), evidence["evidenceSha256"])

      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": {"repository": "source", "commit": commit},
        "sourceDateEpoch": record["commitTime"],
        "repositories": [record],
        "relationships": [],
      }
      bind_source_tree_manifest(lock, {"source": bare})
      validate_contract(lock, "source-lock", REPOSITORY_ROOT / "schemas")
      source_root = Path(directory) / "workspace"
      materialize(lock, {"source": bare}, source_root)
      verify_materialized(lock, source_root)

  def test_build_source_lock_supports_declared_and_component_scoped_licenses(self):
    with tempfile.TemporaryDirectory() as directory:
      self_checkout, self_bare, self_commit = create_repository(directory, "build-tools")
      self_origin = "https://github.com/sunwayking/JetOnlyOffice-build-tools.git"
      run_git(self_checkout, "remote", "add", "origin", self_origin)
      component_checkout, component_bare, _ = create_repository(directory, "fonts")
      payload = b"font payload\n"
      license_text = b"font terms\n"
      (component_checkout / "fonts").mkdir()
      (component_checkout / "fonts" / "Example.ttf").write_bytes(payload)
      (component_checkout / "fonts" / "LICENSE.txt").write_bytes(license_text)
      run_git(component_checkout, "add", "fonts")
      run_git(component_checkout, "commit", "-m", "add font payload")
      component_commit = run_git(component_checkout, "rev-parse", "HEAD^{commit}")
      run_git(component_checkout, "tag", "v1.0.0")
      run_git(
        component_bare,
        "fetch",
        str(component_checkout),
        f"{component_commit}:refs/heads/main",
        "refs/tags/v1.0.0:refs/tags/v1.0.0",
      )
      build_tools = repository_input("build-tools", self_commit)
      del build_tools["commit"]
      build_tools["commitSource"] = "self"
      build_tools["selection"] = {"type": "self"}
      build_tools["origin"] = self_origin
      fonts = repository_input("fonts", component_commit)
      fonts["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.ttf"],
        "patterns": ["**/LICENSE*"],
        "reason": "All components are resolved.",
        "reviewedComponents": [{
          "id": "fonts",
          "spdx": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
          "evidence": [{
            "type": "git-blob",
            "path": "fonts/Example.ttf",
            "locator": "fonts/LICENSE.txt",
            "sha256": hashlib.sha256(license_text).hexdigest(),
          }],
        }],
        "unresolvedComponents": [],
      }
      inputs = {
        "schemaVersion": 1,
        "productVersion": "9.4.0",
        "releaseCutoff": 2000000000,
        "baseline": {"repository": "fonts", "commit": component_commit},
        "repositories": [build_tools, fonts],
        "relationships": [],
      }
      validate_inputs(inputs)
      caches = {"build-tools": self_bare, "fonts": component_bare}

      with patch(
        "source_resolver.sync_cache",
        side_effect=lambda repository, _cache, _commit: caches[repository["id"]],
      ):
        lock, _ = build_source_lock(inputs, Path(directory) / "cache", self_checkout)

      validate_contract(lock, "source-lock", REPOSITORY_ROOT / "schemas")
      self.assertIn("path", lock["repositories"][0]["license"])
      self.assertEqual("component", lock["repositories"][1]["license"]["scope"])

  def test_repository_metadata_records_locked_lfs_objects_and_paths(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      bare, commit, oid, content = add_lfs_object(directory, checkout)
      repository = repository_input("source", commit)

      record = repository_metadata(repository, bare, commit)

      self.assertEqual([{
        "oid": oid,
        "size": len(content),
        "paths": ["asset.bin"],
      }], record["lfsObjects"])

      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": {"repository": "source", "commit": commit},
        "sourceDateEpoch": record["commitTime"],
        "repositories": [record],
        "relationships": [],
      }
      payload = bind_source_tree_manifest(lock, {"source": bare})
      manifest = json.loads(payload)
      validate_contract(
        manifest, "source-tree-manifest", REPOSITORY_ROOT / "schemas"
      )
      entry = next(
        item for item in manifest["repositories"][0]["entries"]
        if item["path"] == "asset.bin"
      )
      pointer = (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{oid}\n"
        f"size {len(content)}\n"
      ).encode("ascii")
      self.assertEqual(run_git(bare, "rev-parse", commit + ":asset.bin"), entry["oid"])
      self.assertEqual(hashlib.sha256(pointer).hexdigest(), entry["sha256"])
      self.assertEqual(
        {"size": len(content), "sha256": oid}, entry["materialized"]
      )
      self.assertEqual(len(payload), lock["sourceTreeManifest"]["size"])
      self.assertEqual(
        hashlib.sha256(payload).hexdigest(),
        lock["sourceTreeManifest"]["sha256"],
      )

  def test_source_tree_manifest_records_symlinks_and_declared_gitlinks(self):
    with tempfile.TemporaryDirectory() as directory:
      _, child_bare, child_commit = create_repository(directory, "child")
      parent_checkout, _, _ = create_repository(directory, "parent")
      target = Path(directory) / "link-target"
      target.write_bytes(b"content.txt")
      symlink_blob = run_git(parent_checkout, "hash-object", "-w", str(target))
      run_git(
        parent_checkout,
        "update-index",
        "--add",
        "--cacheinfo",
        f"120000,{symlink_blob},content-link",
      )
      run_git(
        parent_checkout,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{child_commit},nested/child",
      )
      run_git(parent_checkout, "commit", "-m", "add source tree object types")
      parent_commit = run_git(parent_checkout, "rev-parse", "HEAD^{commit}")
      parent_bare = Path(directory) / "parent-final.git"
      run_git(directory, "clone", "--bare", str(parent_checkout), str(parent_bare))
      child = repository_metadata(
        repository_input("child", child_commit), child_bare, child_commit
      )
      parent = repository_metadata(
        repository_input("parent", parent_commit), parent_bare, parent_commit
      )
      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": {"repository": "parent", "commit": parent_commit},
        "sourceDateEpoch": max(child["commitTime"], parent["commitTime"]),
        "repositories": [child, parent],
        "relationships": [{
          "parent": "parent",
          "child": "child",
          "path": "nested/child",
          "mode": "160000",
        }],
      }

      payload = bind_source_tree_manifest(
        lock, {"child": child_bare, "parent": parent_bare}
      )
      manifest = json.loads(payload)
      validate_contract(
        manifest, "source-tree-manifest", REPOSITORY_ROOT / "schemas"
      )
      parent_tree = next(
        item for item in manifest["repositories"] if item["id"] == "parent"
      )
      by_path = {item["path"]: item for item in parent_tree["entries"]}
      self.assertEqual("symlink", by_path["content-link"]["type"])
      self.assertEqual("120000", by_path["content-link"]["mode"])
      self.assertEqual(symlink_blob, by_path["content-link"]["oid"])
      self.assertEqual("gitlink", by_path["nested/child"]["type"])
      self.assertEqual(child_commit, by_path["nested/child"]["oid"])

  def test_declared_lfs_license_binds_pointer_and_materialized_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      license_bytes = b"materialized LFS license text\n"
      bare, commit, oid, _ = add_lfs_object(
        directory, checkout, name="LICENSE", content=license_bytes
      )
      repository = repository_input("source", commit)
      record = repository_metadata(repository, bare, commit)
      license_record = record["license"]
      self.assertEqual(oid, record["lfsObjects"][0]["oid"])
      self.assertNotEqual(
        license_record["sha256"], license_record["materializedSha256"]
      )
      self.assertEqual(
        hashlib.sha256(license_bytes).hexdigest(),
        license_record["materializedSha256"],
      )
      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": {"repository": "source", "commit": commit},
        "sourceDateEpoch": record["commitTime"],
        "repositories": [record],
        "relationships": [],
      }
      bind_source_tree_manifest(lock, {"source": bare})
      validate_contract(lock, "source-lock", REPOSITORY_ROOT / "schemas")
      source_root = Path(directory) / "workspace"
      materialize(lock, {"source": bare}, source_root)
      verify_materialized(lock, source_root)

  def test_lfs_fetch_uses_anonymous_project_mirror_batch(self):
    repository = repository_input("source")
    lfs_objects = [{"oid": "c" * 64, "size": 1, "paths": ["asset.bin"]}]
    with (
      patch(
        "source_resolver._fetch_anonymous_lfs_actions",
        return_value={"c" * 64: {"href": "https://objects.invalid/source", "headers": {}}},
      ) as fetch_actions,
      patch("source_resolver._download_anonymous_lfs_object") as download,
      patch("source_resolver._verify_lfs_objects"),
      patch("source_resolver._verify_lfs_cache") as verify_cache,
      patch("source_resolver.shutil.copyfile"),
    ):
      fetch_lfs_objects(repository, Path("cache.git"), SHA1_A, lfs_objects)

    fetch_actions.assert_called_once_with(repository, lfs_objects)
    self.assertEqual(repository, download.call_args.args[0])
    self.assertNotIn(repository["upstream"], download.call_args.args[2]["href"])
    verify_cache.assert_called_once()

  def test_lfs_fetch_refreshes_an_expired_download_action(self):
    repository = repository_input("source")
    content = b"public object\n"
    oid = hashlib.sha256(content).hexdigest()
    lfs_object = {"oid": oid, "size": len(content), "paths": ["asset.bin"]}
    expired = {
      oid: {
        "href": "https://objects.invalid/expired",
        "headers": {},
        "expiresIn": 0,
        "fetchedAt": 1,
      }
    }
    fresh = {
      oid: {
        "href": "https://objects.invalid/fresh",
        "headers": {},
        "expiresIn": 3600,
        "fetchedAt": 1,
      }
    }

    def download(_, __, ___, destination):
      destination.parent.mkdir(parents=True, exist_ok=True)
      destination.write_bytes(content)

    with tempfile.TemporaryDirectory() as directory:
      cache = Path(directory) / "cache.git"
      with (
        patch(
          "source_resolver._fetch_anonymous_lfs_actions",
          side_effect=[expired, fresh],
        ) as fetch_actions,
        patch("source_resolver._download_anonymous_lfs_object", side_effect=download),
        patch("source_resolver._verify_lfs_cache"),
        patch("source_resolver.time.time", return_value=1),
      ):
        fetch_lfs_objects(repository, cache, SHA1_A, [lfs_object])

    self.assertEqual(2, fetch_actions.call_count)

  def test_lfs_fetch_refreshes_an_action_rejected_by_object_storage(self):
    repository = repository_input("source")
    content = b"public object\n"
    oid = hashlib.sha256(content).hexdigest()
    lfs_object = {"oid": oid, "size": len(content), "paths": ["asset.bin"]}
    action = {oid: {"href": "https://objects.invalid/source", "headers": {}}}

    def download(_, __, ___, destination):
      if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.touch()
        raise LfsActionRefreshRequired("expired action")
      destination.write_bytes(content)

    with tempfile.TemporaryDirectory() as directory:
      cache = Path(directory) / "cache.git"
      with (
        patch("source_resolver._fetch_anonymous_lfs_actions", return_value=action) as fetch_actions,
        patch("source_resolver._download_anonymous_lfs_object", side_effect=download),
        patch("source_resolver._verify_lfs_cache"),
      ):
        fetch_lfs_objects(repository, cache, SHA1_A, [lfs_object])

    self.assertEqual(2, fetch_actions.call_count)

  def test_anonymous_lfs_batch_rejects_missing_objects_without_credentials(self):
    repository = repository_input("source")
    oid = "c" * 64
    lfs_objects = [{"oid": oid, "size": 1, "paths": ["asset.bin"]}]
    available = io.BytesIO(json.dumps({
      "objects": [{
        "oid": oid,
        "size": 1,
        "actions": {
          "download": {"href": "https://objects.invalid/source"},
        },
      }],
    }).encode("utf-8"))
    with patch(
      "source_resolver._open_anonymous_request",
      return_value=available,
    ) as open_request:
      actions = _fetch_anonymous_lfs_actions(repository, lfs_objects)
    request = open_request.call_args.args[0]
    self.assertEqual(
      repository["origin"] + "/info/lfs/objects/batch",
      request.full_url,
    )
    self.assertIsNone(request.get_header("Authorization"))
    self.assertEqual("https://objects.invalid/source", actions[oid]["href"])

    missing = io.BytesIO(json.dumps({
      "objects": [{
        "oid": oid,
        "size": 1,
        "error": {"code": 404, "message": "missing"},
      }],
    }).encode("utf-8"))
    with patch("source_resolver._open_anonymous_request", return_value=missing):
      with self.assertRaisesRegex(ResolutionError, "not anonymously readable"):
        _fetch_anonymous_lfs_actions(repository, lfs_objects)

  def test_anonymous_lfs_download_verifies_size_and_digest(self):
    repository = repository_input("source")
    content = b"public object\n"
    oid = hashlib.sha256(content).hexdigest()
    lfs_object = {"oid": oid, "size": len(content), "paths": ["asset.bin"]}
    action = {"href": "https://objects.invalid/source", "headers": {}}
    with tempfile.TemporaryDirectory() as directory:
      destination = Path(directory) / oid
      with patch(
        "source_resolver._open_anonymous_request",
        return_value=io.BytesIO(content),
      ):
        _download_anonymous_lfs_object(
          repository,
          lfs_object,
          action,
          destination,
        )
      self.assertEqual(content, destination.read_bytes())

      with patch(
        "source_resolver._open_anonymous_request",
        side_effect=lambda *_: io.BytesIO(b"tampered\n"),
      ):
        with self.assertRaisesRegex(ResolutionError, "does not match lock"):
          _download_anonymous_lfs_object(
            repository,
            lfs_object,
            action,
            destination,
          )

  def test_lfs_public_audit_binds_anonymous_objects_to_locked_commit(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      bare, commit, oid, content = add_lfs_object(directory, checkout)
      repository = repository_input("lfs-source", commit)
      run_git(bare, "remote", "set-url", "origin", repository["origin"])
      inputs = {"productVersion": "9.4.0", "repositories": [repository]}

      cache_root = Path(directory) / "cache"
      cache = cache_root / "git" / "lfs-source.git"
      cache.parent.mkdir(parents=True)
      bare.rename(cache)
      with patch("source_resolver.fetch_lfs_objects") as fetch_objects:
        report = lfs_public_audit_report(
          inputs,
          cache_root,
          ["lfs-source"],
        )

      self.assertEqual("passed", report["status"])
      record = report["repositories"][0]
      self.assertEqual("none", record["repositoryAuthentication"])
      self.assertEqual(1, record["objectCount"])
      self.assertEqual(len(content), record["totalBytes"])
      self.assertEqual(oid, record["objects"][0]["oid"])
      fetch_objects.assert_called_once()

      with self.assertRaisesRegex(ResolutionError, "sorted, unique"):
        lfs_public_audit_report(inputs, cache_root, ["z", "a"])

  def test_powershell_audit_commands_have_distinct_default_reports(self):
    script = (REPOSITORY_ROOT / "scripts" / "resolve-sources.ps1").read_text(
      encoding="utf-8"
    )
    self.assertIn("source-input-audit.json", script)
    self.assertIn("source-license-audit.json", script)
    self.assertIn("source-lfs-public-audit.json", script)
    self.assertIn("source-selection-audit.json", script)

  def test_audit_cli_validates_contract_before_writing_report(self):
    invalid_report = {
      "schemaVersion": 1,
      "auditType": "source-lfs-public",
      "productVersion": "9.4.0",
      "status": "passed",
      "repositories": [],
    }
    with tempfile.TemporaryDirectory() as directory:
      inputs_path = Path(directory) / "inputs.json"
      report_path = Path(directory) / "report.json"
      inputs_path.write_text(json.dumps(source_inputs()), encoding="utf-8")
      with patch(
        "source_resolver.lfs_public_audit_report",
        return_value=invalid_report,
      ):
        exit_code = main([
          "lfs-audit",
          "--inputs", str(inputs_path),
          "--cache-directory", str(Path(directory) / "cache"),
          "--repository", "documentserver",
          "--report", str(report_path),
          "--schema-dir", str(REPOSITORY_ROOT / "schemas"),
        ])

      self.assertEqual(2, exit_code)
      self.assertFalse(report_path.exists())

  def test_selection_audit_cli_validates_contract_before_writing_report(self):
    invalid_report = {
      "schemaVersion": 1,
      "auditType": "source-selection",
      "productVersion": "9.4.0",
      "releaseCutoff": 100,
      "status": "passed",
      "repositories": [],
    }
    with tempfile.TemporaryDirectory() as directory:
      inputs_path = Path(directory) / "inputs.json"
      report_path = Path(directory) / "report.json"
      inputs_path.write_text(json.dumps(source_inputs()), encoding="utf-8")
      with patch(
        "source_resolver.selection_audit_report",
        return_value=invalid_report,
      ):
        exit_code = main([
          "selection-audit",
          "--inputs", str(inputs_path),
          "--cache-directory", str(Path(directory) / "cache"),
          "--self-root", str(Path(directory) / "self"),
          "--report", str(report_path),
          "--schema-dir", str(REPOSITORY_ROOT / "schemas"),
        ])

      self.assertEqual(2, exit_code)
      self.assertFalse(report_path.exists())

  def test_selection_audit_cli_removes_stale_report_before_failed_rerun(self):
    with tempfile.TemporaryDirectory() as directory:
      inputs_path = Path(directory) / "inputs.json"
      report_path = Path(directory) / "selection-audit.json"
      inputs_path.write_text(json.dumps(source_inputs()), encoding="utf-8")
      report_path.write_text('{"status":"passed"}\n', encoding="utf-8")
      with patch(
        "source_resolver.selection_audit_report",
        side_effect=ResolutionError("public mirror is unavailable", 3),
      ):
        exit_code = main([
          "selection-audit",
          "--inputs", str(inputs_path),
          "--cache-directory", str(Path(directory) / "cache"),
          "--self-root", str(Path(directory) / "self"),
          "--report", str(report_path),
          "--schema-dir", str(REPOSITORY_ROOT / "schemas"),
        ])

      self.assertEqual(3, exit_code)
      self.assertFalse(report_path.exists())

  def test_audit_clis_remove_stale_reports_before_contract_failure(self):
    with tempfile.TemporaryDirectory() as directory:
      inputs_path = Path(directory) / "invalid-inputs.json"
      inputs_path.write_text("{}\n", encoding="utf-8")
      commands = [
        ("audit", ["--report"]),
        (
          "license-audit",
          [
            "--cache-directory", str(Path(directory) / "cache"),
            "--report",
            "--schema-dir", str(REPOSITORY_ROOT / "schemas"),
          ],
        ),
        (
          "lfs-audit",
          [
            "--cache-directory", str(Path(directory) / "cache"),
            "--repository", "documentserver",
            "--report",
            "--schema-dir", str(REPOSITORY_ROOT / "schemas"),
          ],
        ),
      ]
      for command, arguments in commands:
        with self.subTest(command=command):
          report_path = Path(directory) / f"{command}.json"
          report_path.write_text('{"status":"passed"}\n', encoding="utf-8")
          report_index = arguments.index("--report") + 1
          arguments = list(arguments)
          arguments.insert(report_index, str(report_path))

          exit_code = main([
            command,
            "--inputs", str(inputs_path),
            *arguments,
          ])

          self.assertEqual(2, exit_code)
          self.assertFalse(report_path.exists())

  def test_resolve_cli_removes_stale_lock_before_license_failure(self):
    inputs = source_inputs()
    inputs["repositories"][1]["license"] = {
      "status": "missing",
      "payloadPatterns": ["**/*.bin"],
      "reason": "test payload license is unresolved",
      "unresolvedComponents": ["payload"],
    }
    with tempfile.TemporaryDirectory() as directory:
      inputs_path = Path(directory) / "inputs.json"
      lock_path = Path(directory) / "sources.lock.json"
      inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
      lock_path.write_text('{"lockType":"source"}\n', encoding="utf-8")

      exit_code = main([
        "resolve",
        "--inputs", str(inputs_path),
        "--cache-directory", str(Path(directory) / "cache"),
        "--lock-output", str(lock_path),
        "--self-root", str(Path(directory) / "self"),
        "--schema-dir", str(REPOSITORY_ROOT / "schemas"),
      ])

      self.assertEqual(3, exit_code)
      self.assertFalse(lock_path.exists())

  def test_lfs_fetch_does_not_trust_objects_already_in_cache(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      bare, commit, oid, content = add_lfs_object(directory, checkout)
      repository = repository_input("source", commit)
      repository["origin"] = "http://127.0.0.1:9/unavailable.git"
      lfs_objects = [{"oid": oid, "size": len(content), "paths": ["asset.bin"]}]

      with self.assertRaises(ResolutionError):
        fetch_lfs_objects(repository, bare, commit, lfs_objects)

  def test_public_mirror_probe_fails_when_anonymous_refs_are_unavailable(self):
    repository = repository_input("source")
    with patch("source_resolver._run_anonymous_git", return_value="") as anonymous_git:
      with self.assertRaisesRegex(ResolutionError, "not anonymously readable"):
        verify_public_mirror(repository)
    self.assertEqual(
      ["ls-remote", "--refs", repository["origin"]],
      anonymous_git.call_args.args[0],
    )

  def test_relationship_verification_rejects_gitlink_drift(self):
    with tempfile.TemporaryDirectory() as directory:
      child_checkout, child_bare, child_commit = create_repository(directory, "child")
      parent_checkout, _, _ = create_repository(directory, "parent")
      run_git(
        parent_checkout,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{child_commit},child",
      )
      run_git(parent_checkout, "commit", "-m", "add child gitlink")
      parent_commit = run_git(parent_checkout, "rev-parse", "HEAD^{commit}")
      parent_bare = Path(directory) / "parent-final.git"
      run_git(directory, "clone", "--bare", str(parent_checkout), str(parent_bare))
      inputs = {
        "relationships": [{
          "parent": "parent",
          "child": "child",
          "path": "child",
          "mode": "160000",
        }]
      }
      caches = {"parent": parent_bare, "child": child_bare}
      commits = {"parent": parent_commit, "child": child_commit}
      verify_relationships(inputs, caches, commits)
      commits["child"] = SHA1_A
      with self.assertRaisesRegex(ResolutionError, "gitlink does not match"):
        verify_relationships(inputs, caches, commits)
      self.assertTrue(child_checkout.is_dir())

  def test_relationship_verification_rejects_unlocked_gitlink(self):
    with tempfile.TemporaryDirectory() as directory:
      _, child_bare, child_commit = create_repository(directory, "child")
      parent_checkout, _, _ = create_repository(directory, "parent")
      run_git(
        parent_checkout,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{child_commit},nested/child",
      )
      run_git(parent_checkout, "commit", "-m", "add undeclared child gitlink")
      parent_commit = run_git(parent_checkout, "rev-parse", "HEAD^{commit}")
      parent_bare = Path(directory) / "parent-final.git"
      run_git(directory, "clone", "--bare", str(parent_checkout), str(parent_bare))

      with self.assertRaisesRegex(
        ResolutionError,
        "parent:nested/child: gitlink is not declared",
      ):
        verify_relationships(
          {"relationships": []},
          {"parent": parent_bare, "child": child_bare},
          {"parent": parent_commit, "child": child_commit},
        )

  def test_materialize_produces_detached_clean_locked_checkout(self):
    with tempfile.TemporaryDirectory() as directory:
      repository, bare, commit, lock = create_source_lock(directory)
      validate_contract(lock, "source-lock", REPOSITORY_ROOT / "schemas")
      source_root = Path(directory) / "workspace"
      materialize(lock, {"source": bare}, source_root)
      checkout = source_root / "sources" / "source"
      self.assertEqual(commit, run_git(checkout, "rev-parse", "HEAD"))
      self.assertEqual("HEAD", run_git(checkout, "rev-parse", "--abbrev-ref", "HEAD"))
      self.assertEqual(repository["origin"], run_git(checkout, "remote", "get-url", "origin"))
      self.assertEqual(
        repository["origin"] + "/info/lfs",
        run_git(checkout, "config", "--local", "--get", "lfs.url"),
      )
      self.assertEqual("", run_git(checkout, "status", "--porcelain"))

  def test_materialize_is_idempotent_for_a_matching_locked_workspace(self):
    with tempfile.TemporaryDirectory() as directory:
      _, bare, _, lock = create_source_lock(directory)
      source_root = Path(directory) / "workspace"

      materialize(lock, {"source": bare}, source_root)
      materialize(lock, {"source": bare}, source_root)

      verify_materialized(lock, source_root)

  def test_materialize_rejects_ignored_files_in_a_reused_checkout(self):
    with tempfile.TemporaryDirectory() as directory:
      _, bare, _, lock = create_source_lock(directory)
      source_root = Path(directory) / "workspace"
      materialize(lock, {"source": bare}, source_root)
      checkout = source_root / "sources" / "source"
      (checkout / ".git" / "info" / "exclude").write_text(
        "ignored.bin\n", encoding="ascii"
      )
      (checkout / "ignored.bin").write_bytes(b"unlocked build input\n")

      with self.assertRaisesRegex(ResolutionError, "checkout is dirty"):
        materialize(lock, {"source": bare}, source_root)

  def test_materialize_rejects_index_flags_that_hide_worktree_changes(self):
    for flag in ("--skip-worktree", "--assume-unchanged"):
      with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
        _, bare, _, lock = create_source_lock(directory)
        source_root = Path(directory) / "workspace"
        materialize(lock, {"source": bare}, source_root)
        checkout = source_root / "sources" / "source"
        run_git(checkout, "update-index", flag, "content.txt")
        (checkout / "content.txt").write_text("hidden change\n", encoding="ascii")

        with self.assertRaisesRegex(ResolutionError, "unsafe Git index flag"):
          materialize(lock, {"source": bare}, source_root)

  def test_materialize_rejects_files_outside_locked_checkouts(self):
    with tempfile.TemporaryDirectory() as directory:
      _, bare, _, lock = create_source_lock(directory)
      source_root = Path(directory) / "workspace"
      materialize(lock, {"source": bare}, source_root)
      (source_root / "unlocked.txt").write_bytes(b"unlocked build input\n")

      with self.assertRaisesRegex(ResolutionError, "unexpected path"):
        materialize(lock, {"source": bare}, source_root)

  def test_materialize_does_not_publish_a_partial_workspace(self):
    with tempfile.TemporaryDirectory() as directory:
      _, first_bare, first_commit = create_repository(directory, "first")
      _, second_bare, second_commit = create_repository(directory, "second")
      first = repository_metadata(
        repository_input("first", first_commit), first_bare, first_commit
      )
      second = repository_metadata(
        repository_input("second", second_commit), second_bare, second_commit
      )
      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": {"repository": "first", "commit": first_commit},
        "sourceDateEpoch": max(first["commitTime"], second["commitTime"]),
        "repositories": [first, second],
        "relationships": [],
      }
      bind_source_tree_manifest(
        lock, {"first": first_bare, "second": second_bare}
      )
      source_root = Path(directory) / "workspace"

      with self.assertRaises(ResolutionError):
        materialize(
          lock,
          {"first": first_bare, "second": Path(directory) / "missing.git"},
          source_root,
        )

      self.assertFalse(source_root.exists())

  def test_materialize_reports_a_staging_cleanup_failure(self):
    with tempfile.TemporaryDirectory() as directory:
      _, _, _, lock = create_source_lock(directory)
      source_root = Path(directory) / "workspace"

      with patch("source_resolver.shutil.rmtree", side_effect=OSError("busy")):
        with self.assertRaisesRegex(ResolutionError, "cannot clean source staging"):
          materialize(
            lock,
            {"source": Path(directory) / "missing.git"},
            source_root,
          )

      self.assertFalse(source_root.exists())

  def test_materialize_restores_and_verifies_lfs_content_without_download(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      bare, commit, oid, content = add_lfs_object(directory, checkout)
      repository = repository_input("source", commit)
      record = repository_metadata(repository, bare, commit)
      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": {"repository": "source", "commit": commit},
        "sourceDateEpoch": record["commitTime"],
        "repositories": [record],
        "relationships": [],
      }
      bind_source_tree_manifest(lock, {"source": bare})
      validate_contract(lock, "source-lock", REPOSITORY_ROOT / "schemas")
      source_root = Path(directory) / "workspace"

      materialize(lock, {"source": bare}, source_root)

      materialized = source_root / "sources" / "source" / "asset.bin"
      self.assertEqual(content, materialized.read_bytes())
      incomplete_lock = json.loads(json.dumps(lock))
      incomplete_lock["repositories"][0]["lfsObjects"] = []
      with self.assertRaisesRegex(ResolutionError, "manifest does not match"):
        verify_materialized(incomplete_lock, source_root)
      materialized.write_bytes(b"tampered\n")
      with self.assertRaisesRegex(ResolutionError, "Git LFS size does not match"):
        verify_materialized(lock, source_root)

  @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
  def test_powershell_audit_returns_incomplete_exit_code_and_report(self):
    with tempfile.TemporaryDirectory() as directory:
      report = Path(directory) / "audit.json"
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "resolve-sources.ps1"),
          "-Command",
          "Audit",
          "-AuditReport",
          str(report),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertEqual("failed", json.loads(report.read_text(encoding="utf-8"))["status"])

  @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
  def test_powershell_wrapper_removes_stale_report_before_python_discovery(self):
    with tempfile.TemporaryDirectory() as directory:
      report = Path(directory) / "selection-audit.json"
      report.write_text('{"status":"passed"}\n', encoding="utf-8")
      environment = os.environ.copy()
      environment["PATH"] = ""
      result = subprocess.run(
        [
          str(shutil.which("pwsh")),
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "resolve-sources.ps1"),
          "-Command",
          "SelectionAudit",
          "-SelectionAuditReport",
          str(report),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        check=False,
      )

      self.assertEqual(2, result.returncode, result.stderr)
      self.assertFalse(report.exists())

  @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
  def test_public_bootstrap_fails_closed_when_lock_asset_is_missing(self):
    with tempfile.TemporaryDirectory() as directory:
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "bootstrap-source.ps1"),
          "-Command",
          "Bootstrap",
          "-LockPath",
          str(Path(directory) / "missing.lock.json"),
          "-CacheDirectory",
          str(Path(directory) / "cache"),
          "-SourceDirectory",
          str(Path(directory) / "sources"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked source input is missing", result.stderr)


if __name__ == "__main__":
  unittest.main()
