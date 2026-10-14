#!/usr/bin/env python3
"""Build an OpenWrt/opkg .ipk.

    mkipk.py <data-dir> <control-dir> <output.ipk>

The container is the one opkg on this target actually reads:

    gzip(tar(./debian-binary, ./data.tar.gz, ./control.tar.gz))

NOT a Debian `ar` archive. That distinction is load-bearing and was verified
two ways rather than assumed:

  * opkg-lede (this device: opkg 2024.10.16~38eccbb1) gunzips the file and
    walks the result as a TAR, looking for members named control.tar.gz and
    data.tar.gz. Handed an `!<arch>` header it finds no such member and
    aborts with "Failed to extract control file from <file>".
  * A package downloaded from downloads.openwrt.org (24.10.0, aarch64_cortex-
    a53) starts with 1f 8b 08 00 -- gzip -- and its inner tar holds exactly
    those three members.

An earlier revision of this script wrote the `ar` layout, which no opkg on
24.10 can read. `file` reports the result as "Debian binary package" either
way, so it is not a usable check; test with `gunzip -c pkg.ipk | tar -tf -`.

Everything is timestamped and ordered deterministically so that rebuilding
the same tree produces the same bytes.

control-dir must contain `control`; `postinst`/`prerm`/`conffiles` are
optional. Everything in data-dir becomes data.tar.gz.
"""
import gzip
import io
import os
import sys
import tarfile

# Fixed timestamp for every member: a reproducible archive is easier to diff
# and to re-verify against a rebuild.
MTIME = 1700000000

# Paths whose contents are only ever invoked as programs. Their mode is forced
# rather than taken from the build tree: shipping one of these as 0644 fails at
# run time with "Permission denied", which reads as a broken package rather
# than as a wrong permission bit, and it fails *silently* -- the service starts,
# logs nothing unusual, and never installs a rule. The original package is the
# reference for this: its firewall.sh is 0755, and a build tree that unpacked
# and re-edited the file loses that.
EXEC_PREFIXES = ("etc/init.d/", "etc/hotplug.d/", "etc/uci-defaults/", "usr/libexec/")
EXEC_SUFFIXES = (".sh",)


def _gzip(data: bytes, mtime: int = 0) -> bytes:
    """gzip with a pinned header timestamp (tarfile's w:gz stamps 'now')."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=mtime) as gz:
        gz.write(data)
    return buf.getvalue()


def _walk(src_dir: str):
    """(arcname, fullpath, isdir) for everything under src_dir, sorted.

    Directories are included as members, the way ipkg-build's tar does it and
    the way the feed's own packages are laid out; the tar uses the same `./`
    member-name prefix.
    """
    out = []
    for root, dirs, files in os.walk(src_dir):
        dirs.sort()
        for d in dirs:
            full = os.path.join(root, d)
            rel = os.path.relpath(full, src_dir)
            out.append(("./" + rel + "/", full, True))
        for f in sorted(files):
            full = os.path.join(root, f)
            if f.startswith("."):
                continue
            rel = os.path.relpath(full, src_dir)
            out.append(("./" + rel, full, False))
    out.sort()
    return out


def _tar_bytes(src_dir: str, mtime: int, exec_names=(), root_entry=False) -> bytes:
    """Uncompressed tar of everything under src_dir.

    uid/gid are normalised to 0/root and modes to 0755/0644 so the output does
    not depend on the umask or ownership of the build tree.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        if root_entry:
            ti = tarfile.TarInfo("./")
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.mtime = mtime
            tf.addfile(ti)

        for arcname, full, isdir in _walk(src_dir):
            ti = tf.gettarinfo(full, arcname=arcname)
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.mtime = mtime
            if isdir:
                ti.mode = 0o755
                tf.addfile(ti)
                continue
            # control/postinst/prerm/conffiles handling: anything the caller
            # lists must be executable, everything else is data.
            base = os.path.basename(full)
            rel = arcname[2:] if arcname.startswith("./") else arcname
            if (base in exec_names
                    or rel.startswith(EXEC_PREFIXES)
                    or rel.endswith(EXEC_SUFFIXES)
                    or (ti.mode & 0o100)):
                ti.mode = 0o755
            else:
                ti.mode = 0o644
            with open(full, "rb") as fh:
                tf.addfile(ti, fh)

        # The tar reader expects the trailing zero blocks a normal tar has.
    data = buf.getvalue()
    return data + b"\0" * ((-len(data)) % 1024)


def build(data_dir: str, control_dir: str, out_path: str) -> None:
    control_tar = _tar_bytes(
        control_dir, MTIME, exec_names=("postinst", "prerm", "preinst", "postrm"),
        root_entry=True,
    )
    data_tar = _tar_bytes(data_dir, MTIME)

    control_tgz = _gzip(control_tar)
    data_tgz = _gzip(data_tar)

    # Outer tar: same member names and order as the feed's packages.
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, payload in (
            ("./debian-binary", b"2.0\n"),
            ("./data.tar.gz", data_tgz),
            ("./control.tar.gz", control_tgz),
        ):
            ti = tarfile.TarInfo(name)
            ti.size = len(payload)
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.mtime = MTIME
            tf.addfile(ti, io.BytesIO(payload))

    blob = _gzip(outer.getvalue())

    with open(out_path, "wb") as fh:
        fh.write(blob)

    print(f"wrote {out_path}")
    print(f"  control.tar.gz {len(control_tgz):>10,} bytes")
    print(f"  data.tar.gz    {len(data_tgz):>10,} bytes")
    print(f"  outer (gzip)   {len(blob):>10,} bytes")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    build(sys.argv[1], sys.argv[2], sys.argv[3])
