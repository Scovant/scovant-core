# Third-party notices

- `tldextract` bundles a snapshot of the Public Suffix List
  (https://publicsuffix.org/), licensed under the Mozilla Public License 2.0.
- Runtime dependencies and their licenses: httpx (BSD-3-Clause),
  beautifulsoup4 (MIT), lxml (BSD-3-Clause), tldextract (BSD-3-Clause),
  pydantic (MIT). A full report is attached to every GitHub release.
- Optional `[tokens]` extra: `tiktoken` (MIT; Copyright (c) 2022 OpenAI, Shantanu
  Jain; https://github.com/openai/tiktoken/blob/main/LICENSE). The encoding's split
  pattern and special-token ids are taken from tiktoken's
  `tiktoken_ext/openai_public.py` under the following licence:

    MIT License

    Copyright (c) 2022 OpenAI, Shantanu Jain

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

- Bundled vocabulary `src/scovant_core/analysis/data/o200k_base.tiktoken`: the
  `o200k_base` byte-pair file, downloaded from
  https://openaipublic.blob.core.windows.net/encodings/o200k_base.tiktoken
  (sha256 `446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d`) and
  redistributed unchanged, as the exact file tiktoken itself downloads. It is not
  part of the tiktoken repository and OpenAI publishes no separate licence statement
  for it; no licence is claimed for this file here. It is read from the package only;
  nothing is downloaded at runtime.
