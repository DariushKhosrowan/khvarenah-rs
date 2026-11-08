#!/usr/bin/env python3
"""Bundle the Windows release binaries into a portable zip.

Used by the release workflow (Windows matrix cell). Creates
dist/dastyab-<artifact>-portable.zip from the three freshly built
binaries in target/release/.
"""
import os
import sys
import zipfile

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: bundle_windows.py <artifact>", file=sys.stderr)
        return 2
    base = sys.argv[1]
    release = os.path.join("target", "release")
    bins = ["dastyab.exe", "dastyab-tui.exe", "dastyab-gui.exe"]
    os.makedirs("dist", exist_ok=True)
    out = os.path.join("dist", f"dastyab-{base}-portable.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for b in bins:
            src = os.path.join(release, b)
            if not os.path.exists(src):
                print(f"missing {src}", file=sys.stderr)
                return 1
            zf.write(src, b)
    print(f"wrote {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
