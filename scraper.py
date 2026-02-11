import os
import re
import atexit
from collections import defaultdict, Counter
from hashlib import md5
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs
from bs4 import BeautifulSoup

# -------------------------
# Configuration & Globals
# -------------------------
# Comprehensive English stopword list used to filter out non-meaningful words
# from word-frequency analysis. Words in this set are ignored when building
# the WORD_FREQ counter so the top-N results reflect content-bearing terms.
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

# ── In-memory statistics accumulators ────────────────────────────────
# Maps each hostname (e.g. "ics.uci.edu") → number of unique pages crawled under that subdomain. Populated by _count_subdomain().
SUBDOMAIN_COUNTS = defaultdict(int)

# Tracks which URLs have already been counted for each subdomain so we never
# double-count a page if it is encountered more than once.
# Structure: { hostname: set_of_urls_already_counted }
COUNTED_PER_SUBDOMAIN = defaultdict(set)

# Tuple of (url, word_count) for the single page with the most words seen so far.
# Initialised to an empty URL with zero words; updated in extract_next_links().
LONGEST_PAGE = ("", 0)


# Set of defragmented, fully-qualified URLs that have already been processed.
# Used as a visited-page guard to prevent redundant work.
UNIQUE_PAGES = set()


# Running frequency count of meaningful (non-stopword, length > 1) words seen across all crawled pages. Used to produce the top-50 word report.
WORD_FREQ = Counter()

# Directory where per-page filtered text is written for safety/debugging.
# Created automatically if it does not already exist.
CORPUS_DIRECTORY = "data/corpus"
os.makedirs(CORPUS_DIRECTORY, exist_ok=True)

# Pages larger than this byte threshold are skipped to avoid memory issues with unusually large or binary-embedded HTML responses.
MAX_PAGE_SIZE = 5_000_000

# Pages whose visible text is shorter than this character count are considered low-content (e.g. redirect stubs, empty shells) and are not analysed.
MIN_TEXT_LEN = 50


# Only URLs whose hostname ends with one of these suffixes are crawled.
# Anything outside these four UCI domains is discarded by is_valid().
ALLOWED_SUFFIXES = ("ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu")

# Specific ICS subdomains known to be either behind authentication, intranet-only, or otherwise undesirable. Requests to these hosts are always rejected.
ICS_SUBDOMAIN_BLACKLIST = {"ngs.ics.uci.edu", "grape.ics.uci.edu", "intranet.ics.uci.edu"}

# If any of these substrings appear anywhere in a URL (case-insensitive), the URL is rejected. They target:
#   - student org pages unlikely to hold academic content (wics)
#   - calendar/event listing pages that generate infinite pagination
#   - DokuWiki action URLs that produce near-duplicate or edit/diff views
#   - Export/print formats (PDF, iCal) that are not HTMLs
BLACKLIST_KEYWORDS = {
    "wics", "calendar", "doku", "physics.edu", "eppstein", "gallery",
    "event","events", "ical", "outlook-ical", "share=ical", "print=", 
    "format=pdf", "action=diff", "action=edit", "do=media", "rev="
}

# Detects date segments in URL paths (e.g. /2023/04/15 or /2023-04-15).
# Calendar-driven pages generate a fresh URL for every day in perpetuity,
# creating a "trap" that would exhaust the crawl frontier.
CALENDAR_TRAPS = re.compile(
    r"/(20[0-4][0-9]|19[7-9][0-9])"  # Year (1970-2049)
    r"[-/]"                          # Separator (dash or slash)
    r"(0?[1-9]|1[0-2])"              # Month
    r"[-/]"                          # Separator (dash or slash)
    r"(0?[1-9]|[12][0-9]|3[01])"     # Day
)

# Matches URL paths that end with a non-HTML file extension.
# These resources are not web pages and should not be crawled or returned as candidate links. The list covers images, audio, video, archives, office documents, code artifacts, and other binary formats.
BAD_EXT_RE = re.compile(r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz)$", re.IGNORECASE)

# Tokenisation pattern: a "word" is any contiguous run of ASCII letters or digits.
# Punctuation, whitespace, and unicode characters are treated as delimiters.
WORD_RE = re.compile(r"[a-zA-Z0-9]+")

def scraper(url, resp):
    """
    Entry point called by the crawler framework for every fetched URL.

    Delegates to extract_next_links() to obtain outbound links, then
    filters them through is_valid() before returning. Only successfully
    fetched pages (HTTP 200) are processed.

    Parameters
    ----------
    url  : str  – The URL that was requested by the crawler.
    resp : obj  – Response object with attributes:
                    .status        (int)  HTTP status code
                    .raw_response  (obj)  Requests-like response with .content,
                                         .headers, and .url

    Returns
    -------
    list[str] – Validated outbound URLs to add to the crawl frontier.
    """
    if resp is None or resp.status != 200:
        return []
    
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    """
    Parse an HTML page, collect all outbound <a href> links, and perform
    textual analysis (word count, subdomain counting, word frequency).

    Processing steps
    ----------------
    1. Guard checks – skip on bad status, missing content, oversized body,
       non-HTML content type, or already-visited URL.
    2. Mark the page as visited to prevent reprocessing.
    3. Parse HTML with BeautifulSoup/lxml and collect absolute URLs.
    4. Strip non-content tags (script, style, noscript) then extract text.
    5. If the text meets the minimum length threshold:
       a. Count this page toward its subdomain tally.
       b. Tokenise and count words; update LONGEST_PAGE if applicable.
       c. Filter stopwords and update the global WORD_FREQ counter.
       d. Write filtered text to disk for persistence/debugging.

    Parameters
    ----------
    url  : str – Original requested URL (used as fallback if resp.url absent).
    resp : obj – Response object (see scraper() docstring).

    Returns
    -------
    list[str] – All absolute URLs found on the page (not yet validated).
    """
    if resp is None or resp.status != 200 or resp.raw_response is None:
        return []

    content = getattr(resp.raw_response, "content", None)
    if not content or len(content) > MAX_PAGE_SIZE:
        return []

    # Filter by Content-Type
    headers = getattr(resp.raw_response, "headers", {}) or {}
    if "text/html" not in (headers.get("Content-Type", "") or "").lower():
        return []

    page_url = getattr(resp, "url", None) or url
    page_url, _ = urldefrag(page_url)

    # Skip if already crawled
    if page_url in UNIQUE_PAGES:
        return []
    UNIQUE_PAGES.add(page_url)

    links = []
    try:
        soup = BeautifulSoup(content, "lxml")

        # 1. Extraction: Get all valid links
        for tag in soup.find_all("a", href=True):
            href = (tag.get("href") or "").strip()
            if not href: continue
            absolute = urljoin(page_url, href)
            absolute, _ = urldefrag(absolute)
            links.append(absolute)

        # 2. Textual Analysis: Remove non-content tags (The "Best of" Reference)
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        text = soup.get_text(separator=" ", strip=True)
        if len(text) >= MIN_TEXT_LEN:
            # Subdomain counting
            _count_subdomain(page_url)

            # Tokenization using Regex
            all_words = WORD_RE.findall(text.lower())
            word_count = len(all_words)

            # Update Longest Page
            global LONGEST_PAGE
            if word_count > LONGEST_PAGE[1]:
                LONGEST_PAGE = (page_url, word_count)

            # Frequency filtering (Using global STOPWORDS)
            filtered = [w for w in all_words if w not in STOPWORDS and len(w) > 1]
            WORD_FREQ.update(filtered)

            # Write to disk for safety
            _write_corpus(page_url, " ".join(filtered))

    except Exception as e:
        print(f"Error extracting {page_url}: {e}")

    return links

def _count_subdomain(page_url):
    """
    Increment the unique-page count for the subdomain of page_url.

    Only counts URLs that belong to the uci.edu domain family (either
    exactly "uci.edu" or any subdomain thereof). Each unique URL is
    counted at most once per hostname thanks to COUNTED_PER_SUBDOMAIN.

    Parameters
    ----------
    page_url : str – Defragmented absolute URL of the page being processed.
    """
    host = (urlparse(page_url).hostname or "").lower()
    if "uci.edu" in host and (host == "uci.edu" or host.endswith(".uci.edu")):
        if page_url not in COUNTED_PER_SUBDOMAIN[host]:
            COUNTED_PER_SUBDOMAIN[host].add(page_url)
            SUBDOMAIN_COUNTS[host] += 1

def _write_corpus(page_url, text):
    """
    Write the filtered (stopword-removed) text of a page to the corpus
    directory as a plain-text file.

    The filename is the MD5 hex digest of the URL, which:
      - guarantees uniqueness (no two URLs produce the same hash),
      - avoids filesystem-unsafe characters that appear in URLs,
      - allows the original URL to be recovered by rehashing if needed.

    Parameters
    ----------
    page_url : str – Defragmented absolute URL (used to derive filename).
    text     : str – Space-joined filtered word tokens for this page.
    """
    # Hash URL to create unique filename
    h = md5(page_url.encode("utf-8", errors="ignore")).hexdigest()
    with open(os.path.join(CORPUS_DIRECTORY, f"{h}.txt"), "w", encoding="utf-8") as f:
        f.write(text)
def is_valid(url):
    """
    Determine whether a URL should be added to the crawl frontier.

    A URL passes validation if and only if ALL of the following hold:
      1. Scheme is http or https.
      2. Hostname ends with one of the four allowed UCI suffixes.
      3. Hostname is not on the ICS subdomain blacklist.
      4. Path does not end with a non-HTML file extension.
      5. URL does not contain any blacklisted keywords.
      6. Query string has ≤ 3 parameters and no known trap parameter names.
      7. Path does not contain a calendar date segment (YYYY/MM/DD etc.).
      8. Path does not contain a repeated directory segment (loop detector).
      9. Path depth ≤ 8 slashes and total URL length ≤ 180 characters.

    Parameters
    ----------
    url : str – Absolute URL to evaluate.

    Returns
    -------
    bool – True if the URL is safe to crawl, False otherwise.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}: return False

        host = (parsed.hostname or "").lower()
        if not host or not any(host == s or host.endswith("." + s) for s in ALLOWED_SUFFIXES):
            return False

        if host in ICS_SUBDOMAIN_BLACKLIST: return False

        path = (parsed.path or "").lower()
        if "wp-login.php" in path or BAD_EXT_RE.match(path): return False

        lower_url = url.lower()
        # 1. Expanded Keyword Check
        for bad in BLACKLIST_KEYWORDS:
            if bad in lower_url: return False

        # 2. Query Trap Safeguard (Crucial for UCI ISG Traps)
        qs = parse_qs(parsed.query)
        # Block if more than 3 params OR if specific 'export' params exist
        if len(qs) > 3: return False
        
        trap_params = {"ical", "outlook-ical", "share", "display", "view", "action"}
        if any(k.lower() in trap_params for k in qs.keys()):
            return False

        # 3. Structural & Date Traps
        # Catch date strings in the path
        if CALENDAR_TRAPS.search(path): return False
        
        # Catch deep path loops (e.g., /events/events/events)
        if re.search(r"/(.+/)\1", path): return False 
        
        # 4. Global Limits
        # If the path is too deep or URL too long, it's usually a trap
        if path.count("/") > 8 or len(url) > 180: return False

        return True
    except Exception:
        return False

def _print_report():
    """
    Print a formatted crawl summary to stdout.

    Registered via atexit.register() so it runs automatically when the
    crawler process exits (cleanly or after KeyboardInterrupt). Outputs:
      - Total number of unique pages crawled
      - URL and word count of the longest page
      - Top 50 most-frequent non-stopword words (sorted by count, then alpha)
      - All discovered subdomains and their unique page counts (sorted alpha)
    """
    print("\n" + "="*30 + " CRAWL REPORT " + "="*30)
    print(f"Unique pages: {len(UNIQUE_PAGES)}")
    print(f"Longest page: {LONGEST_PAGE[0]} ({LONGEST_PAGE[1]} words)")
    
    print("\nTop 50 words:")
    for w, c in sorted(WORD_FREQ.items(), key=lambda x: (-x[1], x[0]))[:50]:
        print(f"{w}: {c}")

    print("\nSubdomains:")
    for host in sorted(SUBDOMAIN_COUNTS.keys()):
        print(f"{host}, {SUBDOMAIN_COUNTS[host]}")
    print("="*74 + "\n")

atexit.register(_print_report)
