#!/usr/bin/env python3
# =============================================================================
# [Python Script] [Installer] [Requirements Bootstrap]
# =============================================================================
"""
install.py - generic dependency installer for a folder that contains a requirements file.

Purpose:
- Run this script from ANY working directory.
- It always installs dependencies for the folder it lives in.
- It looks for a requirements file next to itself:
  - requirements.txt (default)
  - requirements-dev.txt (optional, via flag)
  - requirements*.txt (optional, via --req)

Behavior:
- Uses the current Python interpreter (sys.executable).
- Upgrades pip/setuptools/wheel by default (can be disabled).
- Installs using pip with the selected requirements file.
- Optional: create/use a local venv in ".venv" (recommended).

Usage:
  python setup.py
  python setup.py --venv
  python setup.py --venv --dev
  python setup.py --req requirements_ci.txt
  python setup.py --no-upgrade-pip
  python setup.py --print-only

Exit codes:
  0 = success
  1 = general failure
  2 = requirements file not found
  3 = venv creation/usage failed

Notes:
- This script is designed to be copied into any project folder and left there.
- If --venv is used, installs go into <script_dir>/.venv using that venv's python.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import typing as t


def _shell_quote(s: str) -> str:
  if not s:
    return '""'
  if any(c in s for c in [" ", "\t", '"']):
    return '"' + s.replace('"', '\\"') + '"'
  return s


def _log(tag: str, msg: str) -> None:
  print(f"{tag} {msg}")


def _run(cmd: t.List[str], *, cwd: str, print_only: bool) -> int:
  pretty = " ".join(_shell_quote(x) for x in cmd)
  _log("[CMD]", f"{pretty} (cwd={cwd})")
  if print_only:
    return 0

  p = subprocess.run(
    cmd,
    cwd=cwd,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
  )
  if p.stdout:
    for line in p.stdout.splitlines():
      _log("[OUT]", line)
  return p.returncode


def _path_script_dir() -> str:
  return os.path.dirname(os.path.abspath(__file__))


def _pick_requirements_file(script_dir: str, req_name: str) -> str:
  return os.path.join(script_dir, req_name)


def _ensure_file_exists(path: str) -> None:
  if not os.path.isfile(path):
    raise FileNotFoundError(path)


def _venv_paths(venv_dir: str) -> t.Tuple[str, str]:
  if os.name == "nt":
    py = os.path.join(venv_dir, "Scripts", "python.exe")
    pip = os.path.join(venv_dir, "Scripts", "pip.exe")
  else:
    py = os.path.join(venv_dir, "bin", "python")
    pip = os.path.join(venv_dir, "bin", "pip")
  return py, pip


def _create_venv(python_exe: str, venv_dir: str, *, cwd: str, print_only: bool) -> None:
  if os.path.isdir(venv_dir):
    return
  _log("[VENV]", f"Creating venv: {venv_dir}")
  rc = _run([python_exe, "-m", "venv", venv_dir], cwd=cwd, print_only=print_only)
  if rc != 0:
    raise RuntimeError(f"venv creation failed (exit={rc})")


def _pip_install(
  python_exe: str,
  requirements_path: str,
  *,
  cwd: str,
  upgrade_pip: bool,
  extra_pip_args: t.List[str],
  print_only: bool,
) -> None:
  if upgrade_pip:
    _log("[PIP]", "Upgrading pip/setuptools/wheel...")
    rc = _run(
      [python_exe, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"],
      cwd=cwd,
      print_only=print_only,
    )
    if rc != 0:
      raise RuntimeError(f"pip upgrade failed (exit={rc})")

  _log("[PIP]", f"Installing from: {requirements_path}")
  cmd = [python_exe, "-m", "pip", "install", "-r", requirements_path]
  if extra_pip_args:
    cmd.extend(extra_pip_args)

  rc = _run(cmd, cwd=cwd, print_only=print_only)
  if rc != 0:
    raise RuntimeError(f"pip install failed (exit={rc})")


def main(argv: t.List[str]) -> int:
  ap = argparse.ArgumentParser(
    prog="setup.py",
    description="Install dependencies from a requirements file located next to this script.",
  )
  ap.add_argument("--req", default="requirements.txt", help='Requirements file name next to setup.py (default: "requirements.txt").')
  ap.add_argument("--dev", action="store_true", help='Shortcut for --req requirements-dev.txt (ignored if --req is provided explicitly).')
  ap.add_argument("--venv", action="store_true", help='Create/use a local venv at ".venv" (next to this script).')
  ap.add_argument("--venv-dir", default=".venv", help='Venv folder name/path relative to the script directory (default: ".venv").')
  ap.add_argument("--no-upgrade-pip", action="store_true", help="Do not upgrade pip/setuptools/wheel before installing.")
  ap.add_argument("--print-only", action="store_true", help="Print commands only; do not execute.")
  ap.add_argument("--pip-arg", action="append", default=[], help='Extra pip args (repeatable). Example: --pip-arg "--no-deps"')
  args = ap.parse_args(argv)

  script_dir = _path_script_dir()
  cwd = script_dir

  req_name = args.req
  if args.dev and args.req == "requirements.txt":
    req_name = "requirements-dev.txt"
  req_path = _pick_requirements_file(script_dir, req_name)

  try:
    _ensure_file_exists(req_path)
  except FileNotFoundError:
    _log("[ERR]", f"Requirements file not found: {req_path}")
    _log("[INFO]", "Put setup.py next to requirements.txt, or use --req <file>.")
    return 2

  python_exe = sys.executable

  if args.venv:
    venv_dir_abs = os.path.abspath(os.path.join(script_dir, args.venv_dir))
    if shutil.which(python_exe) is None and not os.path.isfile(python_exe):
      _log("[ERR]", f"Python executable not found: {python_exe}")
      return 3
    try:
      _create_venv(python_exe, venv_dir_abs, cwd=cwd, print_only=args.print_only)
      venv_python, _venv_pip = _venv_paths(venv_dir_abs)
      if not args.print_only and not os.path.isfile(venv_python):
        _log("[ERR]", f"venv python not found after creation: {venv_python}")
        return 3
      python_exe = venv_python
      _log("[VENV]", f"Using venv python: {python_exe}")
    except Exception as e:
      _log("[ERR]", str(e))
      return 3

  try:
    _pip_install(
      python_exe,
      req_path,
      cwd=cwd,
      upgrade_pip=not args.no_upgrade_pip,
      extra_pip_args=list(args.pip_arg or []),
      print_only=args.print_only,
    )
  except Exception as e:
    _log("[ERR]", str(e))
    return 1

  _log("[OK]", "Dependencies installed.")
  if args.venv:
    _log("[INFO]", "To use the venv:")
    if os.name == "nt":
      _log("[INFO]", f'  {os.path.join(args.venv_dir, "Scripts", "activate")}')
    else:
      _log("[INFO]", f'  source {os.path.join(args.venv_dir, "bin", "activate")}')
  return 0


if __name__ == "__main__":
  raise SystemExit(main(sys.argv[1:]))
