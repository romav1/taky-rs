"""Dumps a ZIP as Python's zipfile sees it (JSON on stdout): archive comment and, per entry in
archive order, every ZipInfo header field plus the content (hex).

Usage: zipinfo.py <file.zip>   (run with `python -I -B`). Used by
takyctl/tests/pyref_datapackage.rs (S-321).
"""
import json
import sys
import zipfile


def main(path):
    with zipfile.ZipFile(path) as z:
        out = {"comment": z.comment.hex(), "entries": []}
        for i in z.infolist():
            out["entries"].append({
                "filename": i.filename,
                "is_dir": i.is_dir(),
                "compress_type": i.compress_type,
                "create_system": i.create_system,
                "create_version": i.create_version,
                "extract_version": i.extract_version,
                "flag_bits": i.flag_bits,
                "external_attr": i.external_attr,
                "internal_attr": i.internal_attr,
                "extra": i.extra.hex(),
                "comment": i.comment.hex(),
                "date_time": list(i.date_time),
                "file_size": i.file_size,
                "data": z.read(i).hex(),
            })
        if z.testzip() is not None:
            raise SystemExit("bad CRC")
    print(json.dumps(out))


if __name__ == "__main__":
    main(sys.argv[1])
