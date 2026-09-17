"""A small Wikipedia-backed document loader.

Extends LangChain's ``BaseLoader`` (rather than duck-typing a ``load()``
method) so it composes with the rest of the document-loading ecosystem for
free: ``load()``, ``aload()``, and ``load_and_split()`` all come from the
base class, driven by the ``lazy_load()`` generator implemented here.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import wikipedia
from langchain_core.document_loaders import BaseLoader
from langchain_core.documents import Document


class WikipediaLoader(BaseLoader):
    """Load Wikipedia pages matching a search query.

    Unlike ``langchain_community``'s ``WikipediaLoader``, this loader forces
    HTTPS (the ``wikipedia`` package defaults to an HTTP API URL that
    Wikimedia now rejects), sets a descriptive User-Agent, and rate-limits
    requests so bulk loads don't get throttled or blocked.
    """

    def __init__(self, query: str, load_max_docs: int = 4) -> None:
        """Store the search query and validate the requested document count."""
        if not isinstance(query, str):
            raise TypeError("query must be a string")
        if load_max_docs < 1:
            raise ValueError("load_max_docs must be at least 1")

        self.query = query
        self.load_max_docs = load_max_docs

    def lazy_load(self) -> Iterator[Document]:
        """Search Wikipedia and yield up to ``load_max_docs`` page documents."""
        # wikipedia==1.4.0 defaults to an HTTP API URL. Wikimedia's API requires
        # HTTPS, so update the package setting before its first request.
        if wikipedia.wikipedia.API_URL.startswith("http://"):
            wikipedia.wikipedia.API_URL = wikipedia.wikipedia.API_URL.replace(
                "http://", "https://", 1
            )
            wikipedia.API_URL = wikipedia.wikipedia.API_URL
        wikipedia.wikipedia.USER_AGENT = (
            "WikipediaLoader/1.0 (LangChain educational example;contact@fau.edu)"
        )
        wikipedia.USER_AGENT = wikipedia.wikipedia.USER_AGENT

        wikipedia.set_rate_limiting(True, min_wait=timedelta(milliseconds=500))

        # Search for matching page titles, then fetch and yield each full page.
        titles = wikipedia.search(self.query, results=self.load_max_docs)

        for title in titles:
            page = wikipedia.page(title, auto_suggest=False)
            yield Document(
                page_content=page.content,
                metadata={
                    "source": page.url,
                    "title": page.title,
                    "summary": page.summary,
                },
            )


if __name__ == "__main__":
    # Live example: requires internet access.
    loader = WikipediaLoader(query="LangChain", load_max_docs=4)
    documents = loader.load()

    # Print metadata so the loaded sources can be inspected quickly.
    for index, document in enumerate(documents, start=1):
        print(f"Document {index} metadata:")
        print(document.metadata)
