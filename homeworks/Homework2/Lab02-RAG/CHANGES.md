# Lab02-RAG: Changes and Rationale

This document explains every change made to build this homework's RAG
application, starting from the unmodified Lab 02.3 example code in
[`icardei/gensec-code`](https://github.com/icardei/gensec-code)'s
`02_LangChain/07_RAG` directory, and why each change was made. It's
organized to match the git commit history so it can be read alongside
`git log -p` or the GitHub commit-by-commit diff view.

## Starting point

`07_rag_loaddb.py`, `08_rag_docsearch.py`, `09_rag_query.py`, and
`10_chainlit_rag_query.py` are byte-for-byte copies of the lab's original
files (commit `51d7d1f`). This repo isolates them in their own `uv`
project (`pyproject.toml` / `uv.lock`) instead of sharing an environment
with the rest of the course code, per the assignment's requirement to use
`uv` for dependency isolation.

## Commit-by-commit changes

### `51d7d1f` — Start Lab02-RAG from Lab 02.3 07_RAG example code

Baseline only: copied the four `07_RAG` scripts and the sample `rag_data/`
corpus (txt/pdf/docx/md/csv) unmodified, and added a root `.gitignore` so
virtual environments, the generated Chroma database, and API keys never
get committed.

**Why:** the assignment requires the solution to visibly start from the
lab's example code ("A solution that does not follow this requirement
won't receive any credit"), so this commit exists on its own to make that
starting point unambiguous in the git history.

### `85f71e0` — Add custom WikipediaLoader and fix env/API-key wiring

- **`wikipedia_loader.py`**: a custom `WikipediaLoader` that extends
  LangChain's `BaseLoader` (implements `lazy_load()` as a generator;
  `load()`, `aload()`, and `load_and_split()` come from the base class for
  free instead of being hand-rolled). It fixes three real problems with
  `langchain_community`'s stock `WikipediaLoader`:
  - The `wikipedia` package defaults to an **HTTP** API URL, which
    Wikimedia's servers now reject. The loader force-upgrades it to HTTPS
    before the first request.
  - No descriptive **User-Agent** is set by default, which Wikimedia's API
    etiquette expects. The loader sets one.
  - No **rate limiting**, which risks getting throttled or blocked on bulk
    loads. The loader enables `wikipedia.set_rate_limiting`.
  - Covered by `test_wikipedia_loader.py` (2 tests: behavior against a
    mocked Wikipedia API, and an explicit `issubclass(WikipediaLoader,
    BaseLoader)` check).

  **Why:** this is the assignment's hardest-credit "custom functionality"
  option — "Creating a custom loader of your own that extends LangChain's
  `BaseLoader`" — done as a real subclass, not a duck-typed lookalike.

- **Wired the custom loader into `07_rag_loaddb.py`**, replacing the
  `langchain_community` import, and bumped `load_wikipedia()` to pull 2
  pages by default (was 1) to demonstrate multi-document loading.

- **Fixed `load_docs()`**: the original code split each document into
  chunks, printed a chunk count, then only ever stored `splits[0]` —
  silently discarding every other chunk of every document. Changed to
  store all `splits`.

  **Why:** this was a real correctness bug in the example code. A RAG
  app that only indexes the first ~10,000 characters of every document
  can't answer questions about the rest of it, which defeats the point of
  a "NotebookLM-like" tool for anything longer than one chunk.

- **Fixed the `.env` lookup path** in all four scripts. The original lab
  code walks up 3 parent directories from the script to find a
  repo-root `.ENV` file. In this repo's layout
  (`homeworks/Homework2/Lab02-RAG/<script>.py`), that lands one directory
  short, and the real secrets file here is lower-cased `.env`, not
  `.ENV`. Changed to `Path(__file__).resolve().parents[3] / ".env"`,
  which correctly reaches `gensec-mclean-z23569229/.env`.

  **Why:** required by the assignment ("API keys do not show up in your
  source files, but rather are passed in via environment variables") —
  the mechanism only satisfies that requirement if it actually resolves
  to the right file.

### `677cb94` — Document and disable broken ArxivLoader

Reproduced and confirmed the failure: `langchain_community==0.4.2`'s
`ArxivAPIWrapper` calls the old `Search.results()` method from the
`arxiv` package, which was replaced by `arxiv.Client().results(search)`
in `arxiv>=2.0` (this project pins `arxiv>=4.0.1`). This raises
`AttributeError: 'Search' object has no attribute 'results'` on every
call. `langchain_community` itself is deprecated upstream (it prints a
`DeprecationWarning` on import).

`load_arxiv()` is left in place with a docstring explaining the failure,
but its call site at the bottom of `07_rag_loaddb.py` is commented out
rather than left to crash the whole load run.

**Why:** the assignment explicitly asks the demo to show "both its
capabilities as well as its limitations." This is a genuine, reproducible
upstream limitation (not a bug in code written for this homework), so it
is documented rather than silently patched around or hidden.

### `3b1555b` — Replace `hub.pull()` RAG prompt with a local trusted template

The original `09_rag_query.py` and `10_chainlit_rag_query.py` pulled
their prompt with `hub.pull("rlm/rag-prompt")`. As of the currently
installed `langsmith` client, this now raises `ValueError` by default:
pulling a public prompt by owner/name is blocked because such prompts
"may contain untrusted serialized LangChain objects," unless the caller
explicitly passes `dangerously_pull_public_prompt=True`.

Replaced with an explicit local `ChatPromptTemplate` (same wording as the
`rlm/rag-prompt` template) in both files, removing the LangChain Hub
network dependency entirely.

**Why:** setting `dangerously_pull_public_prompt=True` would silence a
real supply-chain warning — deserializing a prompt object pulled from a
public, third-party-writable registry — rather than address it. Writing
the prompt locally removes both the security risk and an unnecessary
network dependency, and it's a design choice worth calling out
explicitly on a security course's homework.

## Other fixes made outside of source code (not committed, environment-only)

These were bugs in the local `.env` file and shell environment, not in
the application code, so they aren't part of the git history — but they
were required to get the app running end-to-end:

- **`.env` had a stray leading `'`** on its `GOOGLE_API_KEY` line, which
  broke `python-dotenv`'s parser for that line and silently left the key
  unset. Fixed by removing the stray character.
- **`GOOGLE_MODEL` was set to `gemini-2.5-flash`**, which Google has since
  retired for new users (`404 NOT_FOUND`, "no longer available to new
  users"). Updated to `gemini-3.6-flash`.

## Verified end-to-end

- `uv run pytest test_wikipedia_loader.py` — 2/2 passing.
- `uv run python 07_rag_loaddb.py` — successfully loaded and embedded
  documents from: two PDX web pages, 2 Wikipedia pages (via the custom
  loader), one GitHub file, one YouTube transcript, and every local file
  in `rag_data/` (txt, pdf, docx, md, csv).
- `uv run python 09_rag_query.py` — asked "What is LangChain?" against
  the live database and received a correct, grounded answer.
- Added a real personal PDF (`22 CFR Part 120 Subpart B`, an ITAR
  regulation excerpt) to `rag_data/pdf/` after the initial load, embedded
  it into the existing database without re-embedding everything else, and
  asked a question whose answer only exists in that document ("What does
  it mean for an item to be designated as Significant Military
  Equipment (SME)?"). Got a correct, specific answer pulled from the new
  content — confirming the "add your own content and query it" capability
  works, not just the bundled sample corpus.

## Known limitations (by design, not hidden)

- **No upload UI.** Adding content means placing a file in the matching
  `rag_data/<type>/` subfolder (or editing a URL/query/ID at the bottom
  of `07_rag_loaddb.py`) and rerunning the loader — there's no
  drag-and-drop in the Chainlit chat interface.
- **Narrow supported formats.** Only txt, PDF, DOCX, Markdown, CSV, plus
  web pages, Wikipedia, one GitHub-file pattern, and YouTube transcripts.
  No images, audio, EPUB, JSON, or PPTX.
- **`ArxivLoader` is broken** upstream, as documented above.
- **Free-tier embedding quota.** `GoogleGenerativeAIEmbeddings` has a
  fairly low rate limit; loading a large document (e.g. a full-length
  book, hundreds of pages) risks a `429 RESOURCE_EXHAUSTED` error partway
  through the load. This wasn't engineered around (e.g. with batching or
  backoff) so it can be shown as a real, current limitation.
