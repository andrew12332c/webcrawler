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
# Merged Stopwords: Ensures we use the full list
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
    "you're","you_ve","your","yours","yourself","yourselves"
}

SUBDOMAIN_COUNTS = defaultdict(int)
COUNTED_PER_SUBDOMAIN = defaultdict(set)
LONGEST_PAGE = ("", 0)
UNIQUE_PAGES = set()
WORD_FREQ = Counter()

# Persistence setup from Reference
CORPUS_DIRECTORY = "data/corpus"
os.makedirs(CORPUS_DIRECTORY, exist_ok=True)

MAX_PAGE_SIZE = 5_000_000
MIN_TEXT_LEN = 50
ALLOWED_SUFFIXES = ("ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu")
ICS_SUBDOMAIN_BLACKLIST = {"ngs.ics.uci.edu", "grape.ics.uci.edu", "intranet.ics.uci.edu"}

# Merged blacklist and Regex patterns
BLACKLIST_KEYWORDS = {"wics", "calendar", "ical", "tribe", "doku", "eppstein", "/events"}
CALENDAR_TRAPS = re.compile(r"/(20[0-4][0-9]|19[7-9][0-9])(/(0?[1-9]|1[0-2])(/(0?[1-9]|[12][0-9]|3[01]))?)?")
BAD_EXT_RE = re.compile(r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz)$", re.IGNORECASE)
WORD_RE = re.compile(r"[a-zA-Z0-9]+")

def scraper(url, resp):
    if resp is None or resp.status != 200:
        return []
    
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
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
    host = (urlparse(page_url).hostname or "").lower()
    if host.endswith(".uci.edu"):
        if page_url not in COUNTED_PER_SUBDOMAIN[host]:
            COUNTED_PER_SUBDOMAIN[host].add(page_url)
            SUBDOMAIN_COUNTS[host] += 1

def _write_corpus(page_url, text):
    # Hash URL to create unique filename
    h = md5(page_url.encode("utf-8", errors="ignore")).hexdigest()
    with open(os.path.join(CORPUS_DIRECTORY, f"{h}.txt"), "w", encoding="utf-8") as f:
        f.write(text)

def is_valid(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}: return False

        host = (parsed.hostname or "").lower()
        if not host or not any(host == s or host.endswith("." + s) for s in ALLOWED_SUFFIXES):
            return False

        if host in ICS_SUBDOMAIN_BLACKLIST: return False

        path = (parsed.path or "").lower()
        if "wp-login.php" in path or BAD_EXT_RE.match(path): return False

        # ADVANCED TRAP DETECTION (The "Best of" Your Code)
        lower_url = url.lower()
        for bad in BLACKLIST_KEYWORDS:
            if bad in lower_url: return False

        # Query Parameter Explosion Heuristic
        qs = parse_qs(parsed.query)
        if len(qs) > 5: return False
        bad_keys = {"do", "ns", "sectok", "tab_files", "image"}
        if any(k.lower() in bad_keys for k in qs.keys()): return False

        # Structural Traps
        if CALENDAR_TRAPS.search(path) and path.count("/") > 4: return False
        if re.search(r"/(.+/)\1", path): return False # Repeating segments
        if path.count("/") > 10 or len(url) > 250: return False

        return True
    except Exception:
        return False

def _print_report():
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
