#!/usr/bin/env python3
# Ported (as-is) from the mayhemheroes fork's harness at the fuzzed commit
# (mayhemheroes/pptx2md@217bd3185771, mayhem/fuzz_parser.py): the whole input buffer is
# fed straight to python-pptx's Presentation() as the .pptx file bytes, with byte 198
# arbitrarily picking the output formatter so picking it never shrinks/perturbs the
# file content itself. This commit predates pptx2md.types/ConversionConfig, so parse()
# takes a raw Presentation + an outputter instance, exactly as it did upstream here.

import sys

import atheris
import fuzz_helpers

# Pre-import the heavy general-purpose dependencies UNINSTRUMENTED (python-pptx, lxml,
# Pillow, rapidfuzz, tqdm): atheris.instrument_imports() instruments every NEW module
# pulled in transitively during its block, and these are large enough that instrumenting
# them too risks blowing past Mayhem's per-run smoketest timeout before a single fuzz
# input ever executes.
import pptx  # noqa: F401
import lxml.etree  # noqa: F401
import PIL  # noqa: F401
import rapidfuzz  # noqa: F401
import tqdm  # noqa: F401

from pptx import Presentation

with atheris.instrument_imports():
    from pptx2md.parser import parse
    import pptx2md.outputter as outputter

from zipfile import BadZipFile
import zlib
import struct

outputter_classes = [outputter.wiki_outputter, outputter.madoko_outputter, outputter.md_outputter]


@atheris.instrument_func
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    if len(data) < 200:
        return -1

    try:
        # Don't want to consume data and invalidate a pptx file, so just use the 199th byte arbitrarily to pick
        out = outputter_classes[data[198] % len(outputter_classes)]('/dev/null')
        with fdp.ConsumeMemoryFile(all_data=True, as_bytes=True) as f:
            pres = Presentation(f)
            parse(pres, out)
    except (SystemExit, BadZipFile, NotImplementedError, zlib.error, struct.error,
            UnicodeDecodeError, EOFError) as e:
        return -1
    except ValueError as e:
        if 'seek' in str(e):
            return -1
        raise e
    except RuntimeError as e:
        if 'encrypted' in str(e):
            return -1
        raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
