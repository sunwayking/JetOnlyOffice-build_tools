#!/usr/bin/env python3
"""Extract CEF license evidence from the locked Chromium resource archive."""

import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


MAX_ARCHIVE_MEMBER_SIZE = 16 * 1024 * 1024
MAX_RESOURCE_SIZE = 8 * 1024 * 1024
GRIT_BROTLI_MAGIC = b"\x1e\x9b"


class CefEvidenceError(ValueError):
  pass


def seven_zip_executable():
  executable = shutil.which("7z") or shutil.which("7zz")
  if executable:
    return executable
  if os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "7-Zip/7z.exe"
    if candidate.is_file():
      return str(candidate)
  raise CefEvidenceError("7-Zip is required for derived archive evidence")


def seven_zip_member_bytes(
  content,
  member_path,
  context,
  executable=None,
  max_bytes=MAX_ARCHIVE_MEMBER_SIZE,
):
  temporary_path = None
  process = None
  try:
    with tempfile.NamedTemporaryFile(suffix=".7z", delete=False) as temporary:
      temporary.write(content)
      temporary_path = Path(temporary.name)
    with tempfile.TemporaryFile() as error_stream:
      process = subprocess.Popen(
        [executable or seven_zip_executable(), "e", "-so", str(temporary_path), member_path],
        stdout=subprocess.PIPE,
        stderr=error_stream,
      )
      if process.stdout is None:
        raise CefEvidenceError(f"{context}: cannot read extracted archive member")
      output = bytearray()
      while True:
        chunk = process.stdout.read(min(64 * 1024, max_bytes - len(output) + 1))
        if not chunk:
          break
        output.extend(chunk)
        if len(output) > max_bytes:
          process.kill()
          process.wait()
          raise CefEvidenceError(f"{context}: derived archive member is too large")
      return_code = process.wait()
      if return_code != 0:
        error_stream.seek(0)
        detail = error_stream.read(64 * 1024).decode("utf-8", "replace").strip()
        raise CefEvidenceError(
          f"{context}: cannot extract archive member: {detail or '7z failed'}"
        )
      return bytes(output)
  except CefEvidenceError:
    raise
  except OSError as error:
    raise CefEvidenceError(f"{context}: cannot extract archive member: {error}") from error
  finally:
    if process is not None:
      if process.stdout is not None:
        process.stdout.close()
      if process.poll() is None:
        process.kill()
        process.wait()
    if temporary_path is not None:
      temporary_path.unlink(missing_ok=True)


def chromium_pak_resource(content, resource_id, context):
  if len(content) < 12 or struct.unpack_from("<I", content, 0)[0] != 5:
    raise CefEvidenceError(f"{context}: unsupported Chromium DataPack")
  encoding = content[4]
  if encoding not in {0, 1, 2}:
    raise CefEvidenceError(f"{context}: invalid Chromium DataPack encoding")
  if content[5:8] != b"\0\0\0":
    raise CefEvidenceError(f"{context}: invalid Chromium DataPack padding")

  resource_count, alias_count = struct.unpack_from("<HH", content, 8)
  resource_table_end = 12 + (resource_count + 1) * 6
  index_end = resource_table_end + alias_count * 4
  if index_end > len(content):
    raise CefEvidenceError(f"{context}: truncated Chromium DataPack index")

  entries = [
    struct.unpack_from("<HI", content, 12 + index * 6)
    for index in range(resource_count + 1)
  ]
  identifiers = [item[0] for item in entries[:-1]]
  offsets = [item[1] for item in entries]
  if identifiers != sorted(set(identifiers)) or any(identifier == 0 for identifier in identifiers):
    raise CefEvidenceError(f"{context}: invalid Chromium resource identifiers")
  if entries[-1][0] != 0:
    raise CefEvidenceError(f"{context}: invalid Chromium DataPack sentinel")
  if offsets != sorted(offsets) or offsets[0] != index_end or offsets[-1] != len(content):
    raise CefEvidenceError(f"{context}: invalid Chromium DataPack offsets")

  aliases = [
    struct.unpack_from("<HH", content, resource_table_end + index * 4)
    for index in range(alias_count)
  ]
  alias_identifiers = [item[0] for item in aliases]
  if (
    alias_identifiers != sorted(set(alias_identifiers))
    or any(identifier == 0 for identifier in alias_identifiers)
  ):
    raise CefEvidenceError(f"{context}: invalid Chromium alias identifiers")
  if set(identifiers).intersection(alias_identifiers):
    raise CefEvidenceError(f"{context}: duplicate identifier across Chromium tables")
  if any(entry_index >= resource_count for _, entry_index in aliases):
    raise CefEvidenceError(f"{context}: invalid Chromium alias index")

  if resource_id in identifiers:
    index = identifiers.index(resource_id)
  else:
    alias_by_id = dict(aliases)
    if resource_id not in alias_by_id:
      raise CefEvidenceError(f"{context}: Chromium resource is missing")
    index = alias_by_id[resource_id]
  resource = content[offsets[index]:offsets[index + 1]]
  if len(resource) > MAX_RESOURCE_SIZE:
    raise CefEvidenceError(f"{context}: Chromium resource is too large")
  return resource


def chromium_grit_brotli(content, context):
  if len(content) <= 8:
    raise CefEvidenceError(f"{context}: Chromium GRIT Brotli resource is truncated")
  if content[:2] != GRIT_BROTLI_MAGIC:
    raise CefEvidenceError(f"{context}: Chromium GRIT Brotli magic does not match")
  declared_size = int.from_bytes(content[2:8], "little")
  if declared_size == 0 or declared_size > MAX_RESOURCE_SIZE:
    raise CefEvidenceError(f"{context}: Chromium GRIT Brotli length is invalid")

  script = (
    "const z=require('node:zlib'),c=[];"
    "process.stdin.on('data',x=>c.push(x));"
    "process.stdin.on('end',()=>{"
    "const input=Buffer.concat(c),limit=Number(process.argv[1]);"
    "const result=z.brotliDecompressSync(input,{maxOutputLength:limit,info:true});"
    "if(result.engine.bytesWritten!==input.length)"
    "throw new Error('trailing Brotli input');"
    "process.stdout.write(result.buffer)});"
  )
  try:
    result = subprocess.run(
      ["node", "-e", script, str(declared_size)],
      input=content[8:],
      check=False,
      capture_output=True,
    )
  except OSError as error:
    raise CefEvidenceError(
      f"{context}: Node.js is required for Chromium GRIT Brotli evidence"
    ) from error
  if result.returncode != 0:
    raise CefEvidenceError(f"{context}: invalid Chromium GRIT Brotli evidence")
  if len(result.stdout) != declared_size:
    raise CefEvidenceError(f"{context}: Chromium GRIT Brotli length does not match")
  return result.stdout


def derived_cef_pak_resource(content, evidence, context):
  pak = seven_zip_member_bytes(content, evidence["archiveMember"], context)
  resource = chromium_pak_resource(pak, evidence["resourceId"], context)
  compression = evidence["compression"]
  if compression == "none":
    return resource
  if compression == "chromium-grit-brotli":
    return chromium_grit_brotli(resource, context)
  raise CefEvidenceError(f"{context}: unsupported CEF resource transform")
