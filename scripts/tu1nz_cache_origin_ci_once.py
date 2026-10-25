"""DRAFT: one fixed cache recipe, no Host access, generator or general operator.

Private release-asset storage, new credentials and exact run admission are NOT
presently approved. This unpublished diff is not an execution authorization.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

IMAGE = "ubuntu@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc"
TOOL = "fad1d7a2d518130510588012ece96eff52cd5afb69f4b75071ee0d9f213ebd2e"
MAX_PACKAGE = 900 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def require(ok):
    if not ok:
        raise ValueError("BOUNDARY")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def closed_environment():
    raw = os.environ.pop("CACHE_ORIGIN_ADMISSION", "")
    token = os.environ.pop("CACHE_ORIGIN_ASSET_READ_TOKEN", "")
    require(0 < len(raw) < 16384 and 0 < len(token) < 4096)
    a = json.loads(raw)
    require(set(a) == {"source_sha", "run_id", "package_sha256", "index_sha256",
                       "asset_id", "approval_sha256", "expires_unix"})
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("GITHUB_REPOSITORY") == "Tausendunde1nz/infra" and
            os.environ.get("GITHUB_EVENT_NAME") == "push" and
            os.environ.get("GITHUB_REF") == "refs/heads/codex/cache-origin-ci-20261024-1" and
            os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and
            os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64" and
            platform.machine() == "x86_64" and os.geteuid() != 0)
    require(re.fullmatch("[a-f0-9]{40}", a["source_sha"]) and
            type(a["run_id"]) is int and a["run_id"] > 0 and
            a["source_sha"] == os.environ.get("GITHUB_SHA") and
            str(a["run_id"]) == os.environ.get("GITHUB_RUN_ID"))
    require(all(re.fullmatch("[a-f0-9]{64}", a[k]) for k in
                ("package_sha256", "index_sha256", "approval_sha256")))
    require(type(a["asset_id"]) is int and a["asset_id"] > 0 and
            type(a["expires_unix"]) is int and time.time() < a["expires_unix"] <= time.time() + 3600)
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], env=ENV, stderr=subprocess.DEVNULL).decode().strip() == a["source_sha"])
    require(not subprocess.check_output(["git", "status", "--porcelain"], env=ENV, stderr=subprocess.DEVNULL))
    return a, token


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        require(u.scheme == "https" and u.hostname == "release-assets.githubusercontent.com" and
                u.port in (None, 443) and u.username is None and u.password is None)
        # Never send the API credential to the signed CDN destination.
        return urllib.request.Request(newurl, headers={"Accept": "application/octet-stream"})


def download(a, token, path):
    url = "https://api.github.com/repos/Tausendunde1nz/control/releases/assets/" + str(a["asset_id"])
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
        "Accept": "application/octet-stream", "X-GitHub-Api-Version": "2022-11-28"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
    start = time.monotonic(); size = 0; h = hashlib.sha256()
    with opener.open(request, timeout=30) as response, path.open("xb") as out:
        require(response.status == 200)
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            require(size <= MAX_PACKAGE and time.monotonic() - start < 120)
            out.write(block); h.update(block)
        out.flush(); os.fsync(out.fileno())
    require(h.hexdigest() == a["package_sha256"])


def extract(path, destination, a):
    # Entire archive is hash-bound BEFORE parsing. No extractall, hardlinks,
    # special objects or following an archive-provided parent symlink.
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        require(len(members) <= 1100 and len({m.name for m in members}) == len(members))
        mi = archive.getmember("PAYLOAD_INDEX.json")
        require(mi.isfile() and mi.size <= 1024 * 1024)
        raw = archive.extractfile(mi).read()
        require(sha(raw) == a["index_sha256"])
        index = json.loads(raw); objects = index["objects"]
        # Exact private index digest binds the single selected dataset. Do not
        # publish its Host-specific file counts/size/fingerprint in source.
        require(0 < len(objects) <= 1100 and set(m.name for m in members) == set(objects) | {mi.name})
        total = 0
        for m in members:
            parts = Path(m.name).parts
            require(parts and not Path(m.name).is_absolute() and ".." not in parts)
            require(m.name == mi.name or parts[0] in ("inputs", "tool", "reference"))
        for m in members:
            if m.name == mi.name:
                continue
            row = objects[m.name]; p = destination / m.name
            require((row["kind"] == "directory" and m.isdir()) or
                    (row["kind"] == "file" and m.isfile()) or
                    (row["kind"] == "link" and m.issym()))
            if m.isdir():
                p.mkdir(parents=True, exist_ok=True)
            elif m.isfile():
                require(m.size == row["bytes"] and 0 <= m.size <= 256 * 1024 * 1024)
                total += m.size; require(total <= MAX_EXPANDED)
                p.parent.mkdir(parents=True, exist_ok=True)
                h = hashlib.sha256()
                with archive.extractfile(m) as src, p.open("xb") as out:
                    while True:
                        block = src.read(1024 * 1024)
                        if not block:
                            break
                        out.write(block); h.update(block)
                require(h.hexdigest() == row["sha256"])
                p.chmod(0o444)
        # Links last: no later extraction ever traverses them.
        for m in members:
            if m.issym():
                row = objects[m.name]; require(m.linkname == row["target"])
                p = destination / m.name; p.parent.mkdir(parents=True, exist_ok=True)
                p.symlink_to(m.linkname)
    tool = destination / "tool/ldconfig.real"
    require(sha(tool.read_bytes()) == TOOL)
    tool.chmod(0o555)
    return destination / "inputs", tool, destination / "reference/HOST_CACHE.bin"


def command(argv, root, *, seconds=30):
    # Child output stays in ONE private bounded scratch file, never public logs.
    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    with (root / "child-output").open("wb") as out:
        return subprocess.run(argv, stdout=out, stderr=out, env=ENV,
                              timeout=seconds, preexec_fn=limit).returncode


def main():
    os.umask(0o077)
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    result = {"status": "NOT_RUN", "comparison": "NOT_PERFORMED", "cleanup": "NOT_STARTED"}
    root = None; container = None; image_id = None
    try:
        a, token = closed_environment()
        result.update(source_sha=a["source_sha"], run_id=a["run_id"])
        parent = Path(os.environ["RUNNER_TEMP"])
        require(parent.is_absolute() and parent.is_dir() and not parent.is_symlink())
        root = Path(tempfile.mkdtemp(prefix="tu1nz-cache-once-", dir=parent))
        identity = root.stat(); require(identity.st_uid == os.geteuid() and stat.S_IMODE(identity.st_mode) == 0o700)
        (root / "docker-config").mkdir(mode=0o700)
        ENV["DOCKER_CONFIG"] = str(root / "docker-config")
        require(shutil.disk_usage(root).free >= 3 * 1024 * 1024 * 1024)
        require(command(["docker", "pull", "--platform=linux/amd64", IMAGE], root, seconds=120) == 0)
        inspect = subprocess.check_output(["docker", "image", "inspect", IMAGE], env=ENV,
                                          stderr=subprocess.DEVNULL, timeout=10)
        image = json.loads(inspect)[0]
        require(image["Architecture"] == "amd64" and
                set(x.split("=", 1)[0] for x in image["Config"]["Env"]) <= {"PATH"})
        image_id = image["Id"]
        download(a, token, root / "package.tar"); token = None
        inputs, tool, reference = extract(root / "package.tar", root / "payload", a)
        out = root / "output"; out.mkdir(mode=0o700)
        container = root.name
        label = "tu1nz.cache.run=" + str(a["run_id"])
        argv = ["docker", "run", "--name", container, "--label", label, "--log-driver=none", "--pull=never", "--platform=linux/amd64",
            "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user", str(os.geteuid()) + ":" + str(os.getegid()), "--pids-limit=32", "--memory=512m", "--cpus=1",
            "--ulimit", "nofile=512:512", "--ulimit", "fsize=1048576:1048576", "--restart=no",
            "--mount", "type=bind,src=" + str(inputs) + ",dst=/inputs,readonly",
            "--mount", "type=bind,src=" + str(tool) + ",dst=/tool/ldconfig.real,readonly",
            "--mount", "type=bind,src=" + str(out) + ",dst=/inputs/out",
            "-e", "LC_ALL=C", "-e", "LANG=C", "-e", "PATH=/nonexistent", "--entrypoint", "/tool/ldconfig.real", image_id,
            "-X", "-i", "-c", "new", "-r", "/inputs", "-C", "/out/cache", "-f", "/etc/ld.so.conf"]
        require(time.time() < a["expires_unix"])
        result["status"] = "GENERATOR_OUTCOME_UNKNOWN"
        result["generator_exit"] = command(argv, root, seconds=30)
        if result["generator_exit"] == 0:
            cache = out / "cache"
            require(cache.is_file() and not cache.is_symlink() and cache.stat().st_size <= 1024 * 1024)
            actual, expected = cache.read_bytes(), reference.read_bytes()
            require(0 < len(expected) <= 1024 * 1024)
            same = actual == expected
            result.update(status="MATCH" if same else "MISMATCH", comparison="PERFORMED",
                          size_equal=len(actual) == len(expected), full_byte_equal=same)
    except BaseException:
        # Never emit exception text/type/traceback/URL/path or child output.
        if result["status"] == "NOT_RUN":
            result["status"] = "ENTRY_OR_INPUT_RED"
    finally:
        ok = True
        if root is not None:
            if container is not None:
                try:
                    value = json.loads(subprocess.check_output(["docker", "inspect", container], env=ENV,
                        stderr=subprocess.DEVNULL, timeout=10))[0]
                    require(value["Name"] == "/" + container and value["Image"] == image_id and
                            value["Config"]["Labels"].get("tu1nz.cache.run") == str(a["run_id"]))
                    require(command(["docker", "rm", "--force", value["Id"]], root, seconds=10) == 0)
                except BaseException:
                    ok = False
            try:
                require(ok)  # Unknown container cleanup: retain own scratch until VM teardown.
                now = root.lstat()
                require(stat.S_ISDIR(now.st_mode) and now.st_uid == os.geteuid() and
                        (now.st_dev, now.st_ino) == (identity.st_dev, identity.st_ino) and
                        root.parent == parent and root.name.startswith("tu1nz-cache-once-"))
                shutil.rmtree(root)
            except BaseException:
                ok = False
        result["cleanup"] = "CONFIRMED_OWN_COPIES" if ok else "UNCONFIRMED"
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "MATCH" and result["cleanup"] == "CONFIRMED_OWN_COPIES" else 1


if __name__ == "__main__":
    raise SystemExit(main())
