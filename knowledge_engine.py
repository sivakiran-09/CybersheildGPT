"""
CyberShield GPT - Knowledge Engine
Real lightweight RAG: reads .txt/.md/.pdf files from documents/,
chunks them, builds a TF-IDF index, and does cosine-similarity search.
No external API or model download required.
"""

import os
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

DOCS_FOLDER = "documents"
CHUNK_SIZE = 800       # characters per chunk
CHUNK_OVERLAP = 150    # overlap between chunks so context isn't cut off

_chunks = []
_sources = []
_vectorizer = None
_matrix = None


def _read_txt(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def _read_pdf(path):
    if PdfReader is None:
        return ""
    reader = PdfReader(path)
    text = ""
    for page in reader.pages:
        text += (page.extract_text() or "") + "\n"
    return text


def _chunk_text(text):
    text = re.sub(r"\s+", " ", text).strip()
    chunks = []
    start = 0
    while start < len(text):
        end = start + CHUNK_SIZE
        chunk = text[start:end].strip()
        if len(chunk) > 40:
            chunks.append(chunk)
        start += CHUNK_SIZE - CHUNK_OVERLAP
    return chunks


def build_index():
    """Scan documents/, read every supported file, chunk it, and build the TF-IDF index."""
    global _chunks, _sources, _vectorizer, _matrix
    _chunks, _sources = [], []

    if not os.path.exists(DOCS_FOLDER):
        os.makedirs(DOCS_FOLDER)

    for filename in sorted(os.listdir(DOCS_FOLDER)):
        path = os.path.join(DOCS_FOLDER, filename)
        if not os.path.isfile(path):
            continue

        lower = filename.lower()
        if lower.endswith(".pdf"):
            text = _read_pdf(path)
        elif lower.endswith((".txt", ".md")):
            text = _read_txt(path)
        else:
            continue

        for chunk in _chunk_text(text):
            _chunks.append(chunk)
            _sources.append(filename)

    if _chunks:
        _vectorizer = TfidfVectorizer(stop_words="english")
        _matrix = _vectorizer.fit_transform(_chunks)
    else:
        _vectorizer = None
        _matrix = None


def search(query, top_k=6):
    """Return the top_k most relevant chunks for the query, ranked by cosine similarity."""
    if not query.strip() or _vectorizer is None:
        return []

    query_vec = _vectorizer.transform([query])
    scores = cosine_similarity(query_vec, _matrix).flatten()
    ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)

    results = []
    for i in ranked[:top_k]:
        if scores[i] <= 0.01:
            continue
        results.append({
            "source": _sources[i],
            "snippet": _chunks[i][:450] + ("..." if len(_chunks[i]) > 450 else ""),
            "score": round(float(scores[i]), 3),
        })
    return results


def list_documents():
    """Distinct source filenames currently indexed."""
    return sorted(set(_sources))


def has_documents():
    return len(_chunks) > 0


def document_count():
    return len(list_documents())


def chunk_count():
    return len(_chunks)