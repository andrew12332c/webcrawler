import os
import re
from collections import defaultdict
from hashlib import md5
from urllib.parse import urlparse, urljoin, urldefrag

from bs4 import BeautifulSoup

# -------------------------
# Stopwords (given)
# -------------------------
STOPWORDS = {
    "a","about","above","after","again","against","all","am","an","and","any",
    "are","aren't","as","at","be","because","been","before","being","below",
    "between","both","but","by","can't","cannot","could","couldn't","did",
    "didn't","do","does","doesn't","doing","don't","down","during","each",
    "few","for","from","further","had","hadn't","has","hasn't","have",
    "haven't","having","he","he'd","he'll","he's","her","here","here's",
    "hers","herself","him","himself","his","how","how's","i","i'd","i'll",
    "i'm","i've","if","in","into","is","isn't","it","it's","its","itself",
    "let's","me","more","most","mustn't","my","myself","no","nor","not","of",
    "off","on","once","only","or","other","ought","our","ours","ourselves",
    "out","over","own","same","shan't","she","she'd","she'll","she's",
    "should","shouldn't","so","some","such","than","that","that's","the",
    "their","theirs","them","themselves","then","there","there's","these",
    "they","they'd","they'll","they're","they've","this","those","through",
    "to","too","under","until","up","very","was","wasn't","we","we'd",
    "we'll","we're","we've","were","weren't","what","what's","when",
    "when's","where","where's","which","while","who","who's","whom","why",
    "why's","with","won't","would","wouldn't","you","you'd","you'll",
    "you're","you've","your","yours","yourself","yourselves"
}

# -------------------------
# Globals / report state
# -------------------------
SUBDOMAIN_COUNTS = defaultdict(int)
COUNTED_PER_SUBDOMAIN = defaultdict(set)

LONGEST_PAGE = ("", 0)  # (url, word_count)

CORPUS_DIRECTORY = "data/corpus"
os.makedirs(CORPUS_DIRECTORY, exist_ok=True)

MAX_PAGE_SIZE = 5_000_000
MIN_TEXT_LEN = 50

# unique pages by URL ignoring fragment (matches spec)
UNIQUE_PAGES = set()

TOTAL_VISITED = 0

ALLOWED_SUFFIXES = ("ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu")

ICS_SUBDOMAIN_BLACKLIST = {"ngs.ics.uci.edu", "grape.ics.uci.edu"}

BLACKLIST_KEYWORDS = {
    "wics", "calendar", "ical", "tribe", "doku", "eppstein", "/events"
}

CALENDAR_TRAPS = re.compile(
    r"/(20[0-4][0-9]|19[7-9][0-9])"
    r"(/(0?[1-9]|1[0-2])"
    r"(/(0?[1-9]|[12][0-9]|3[01]))?)?"
)

BAD_EXTENSIONS = re.compile(
    r".*\.(css|js|bmp|gif|jpe?g|ico"
    r"|png|tiff?|mid|mp2|mp3|mp4"
    r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
    r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
    r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
    r"|epub|dll|cnf|tgz|sha1|thmx|mso|arff|rtf|jar|csv"
    r"|rm|smil|wmv|swf|wma|zip|rar|gz)$",
    re.IGNORECASE
)


def scraper(url, resp):
    """
    Starter flow: extract links, then filter with is_valid.
    We update page-level analytics inside extract_next_links.
    """
    global TOTAL_VISITED
    TOTAL_VISITED += 1
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    """
    - Only parse 200 HTML responses
    - Defragment URLs (spec requirement)
    - Extract <a href> links
    - Extract text and update:
        * UNIQUE_PAGES
        * LONGEST_PAGE
        * SUBDOMAIN_COUNTS
        * write corpus file
    """
    if resp is None or resp.status != 200 or resp.raw_response is None:
        return []

    content = getattr(resp.raw_response, "content", None)
    if not content:
        return []

    if len(content) > MAX_PAGE_SIZE:
        return []

    # canonical URL (handles redirects), then defragment for uniqueness
    page_url = getattr(resp, "url", None) or url
    page_url, _ = urldefrag(page_url)

    # avoid re-processing same page by the assignment definition
    if page_url in UNIQUE_PAGES:
        return []
    UNIQUE_PAGES.add(page_url)

    # only HTML (helps avoid weird non-text content)
    ctype = (resp.raw_response.headers.get("Content-Type", "") or "").lower()
    if "text/html" not in ctype:
        return []

    links = []

    try:
        soup = BeautifulSoup(content, "lxml")

        # extract outgoing links
        for a in soup.find_all("a", href=True):
            href = a.get("href", "").strip()
            if not href:
                continue
            absolute = urljoin(page_url, href)
            absolute, _ = urldefrag(absolute)
            links.append(absolute)

        # remove some non-content tags for cleaner text
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        text = soup.get_text(separator=" ", strip=True)

        # still count subdomain / uniqueness even if low text, but don't save/measure longest
        _count_subdomain(page_url)

        if len(text) < MIN_TEXT_LEN:
            return links

        # compute word count ignoring stopwords (also used for longest page)
        words = re.findall(r"[a-zA-Z0-9']+", text.lower())
        words = [w for w in words if w not in STOPWORDS and len(w) > 1]
        word_count = len(words)

        global LONGEST_PAGE
        if word_count > LONGEST_PAGE[1]:
            LONGEST_PAGE = (page_url, word_count)

        _write_corpus(page_url, " ".join(words))

    except Exception as e:
        print("extract_next_links error:", e)

    return links


def _write_corpus(page_url: str, text: str) -> None:
    file_hash = md5(page_url.encode("utf-8", errors="ignore")).hexdigest()
    filepath = os.path.join(CORPUS_DIRECTORY, f"{file_hash}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(text)


def _count_subdomain(page_url: str) -> None:
    """
    Count subdomains by unique pages (defragmented URL).
    """
    parsed = urlparse(page_url)
    host = (parsed.hostname or "").lower()
    if host.endswith(".uci.edu"):
        if page_url not in COUNTED_PER_SUBDOMAIN[host]:
            COUNTED_PER_SUBDOMAIN[host].add(page_url)
            SUBDOMAIN_COUNTS[host] += 1


def is_valid(url):
    """
    URL filter:
    - only the 4 domain families
    - block obvious non-text files
    - basic trap avoidance
    """
    try:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        host = (parsed.hostname or "").lower()
        if not host:
            return False

        # restrict to assignment domains
        if not _host_allowed(host):
            return False

        if host in ICS_SUBDOMAIN_BLACKLIST:
            return False

        path = (parsed.path or "").lower()

        if "wp-login.php" in path:
            return False

        # extension filter
        if BAD_EXTENSIONS.match(path):
            return False

        lower_url = url.lower()

        # keyword blacklists
        for bad in BLACKLIST_KEYWORDS:
            if bad in lower_url:
                return False

        # calendar trap pattern + deep paths
        if CALENDAR_TRAPS.search(path) and path.count("/") > 4:
            return False

        # repeated path segments trap: /a/a/...
        if re.search(r"/(.+/)\1", path):
            return False

        # depth cap
        if path.count("/") > 12:
            return False

        # length cap (cheap trap guard)
        if len(url) > 200:
            return False

        return True

    except TypeError:
        print("TypeError for", url)
        return False


def _host_allowed(host: str) -> bool:
    for suffix in ALLOWED_SUFFIXES:
        suffix = suffix.lower()
        if host == suffix:
            return True
        if host.endswith("." + suffix):
            return True
    return False
