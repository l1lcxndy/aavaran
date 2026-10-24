"""Build `aavaran-qwen`: qwen2.5vl:7b with the vision input capped to AAVARAN's frames.

Ollama sizes the vision encoder's scratch memory for qwen25vl.vision.max_pixels,
which this model file omits, so it defaults to ~2 MP (a 6.7 GiB reservation).
That cannot fit an 8 GB laptop GPU, and Ollama then runs the whole model on CPU
(~45 s per frame). AAVARAN sends at most egressMaxEdge-px frames, so capping
max_pixels to that lets the model run on the GPU.

    python scripts/make-local-model.py            (needs: pip install gguf; Ollama running)
"""

import gc
import os
import subprocess
import sys
import tempfile

from gguf import GGUFReader, GGUFValueType, GGUFWriter
from gguf.scripts.gguf_new_metadata import MetadataDetails, copy_with_new_metadata

BASE = "qwen2.5vl:7b"
NAME = "aavaran-qwen"
MAX_PIXELS = 1024 * 640   # covers a 1024x576 egress frame with headroom


def main() -> None:
    modelfile = subprocess.run(["ollama", "show", "--modelfile", BASE],
                               capture_output=True, text=True, check=True).stdout
    src = next(l.split(" ", 1)[1].strip() for l in modelfile.splitlines() if l.startswith("FROM "))
    out_dir = tempfile.mkdtemp(prefix="aavaran-qwen-")
    dst = os.path.join(out_dir, "model.gguf")

    reader = GGUFReader(src)
    arch = bytes(reader.fields["general.architecture"].parts[-1]).decode()
    writer = GGUFWriter(dst, arch=arch, endianess=reader.endianess)
    copy_with_new_metadata(reader, writer, {
        f"{arch}.vision.max_pixels": MetadataDetails(GGUFValueType.UINT32, MAX_PIXELS),
    }, [])

    # Self-check before importing: the copy carries the cap and every tensor.
    check = GGUFReader(dst)
    field = check.fields[f"{arch}.vision.max_pixels"]
    assert int(field.parts[field.data[0]][0]) == MAX_PIXELS
    assert len(check.tensors) == len(reader.tensors)
    del check, reader, field
    gc.collect()  # the readers memory-map the files; Windows will not delete a mapped file

    # Same chat template and parameters as the base model; only FROM changes.
    lines = [l for l in modelfile.splitlines() if not l.startswith(("FROM ", "#"))]
    mf = os.path.join(out_dir, "Modelfile")
    with open(mf, "w", encoding="utf-8") as f:
        f.write(f"FROM {dst}\n" + "\n".join(lines) + "\n")
    subprocess.run(["ollama", "create", NAME, "-f", mf], check=True)
    os.remove(dst)
    print(f"created {NAME} (vision.max_pixels={MAX_PIXELS}); temp copy removed")


if __name__ == "__main__":
    sys.exit(main())
