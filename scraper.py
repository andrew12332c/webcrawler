import re
import atexit
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs
from bs4 import BeautifulSoup
from collections import Counter 
# Global
SUBDOMAIN_COUNTS = {}
COUNTED_PER_SUBDOMAIN = {}
LONGEST_PAGE = ("", 0)
TOTAL_VISITED = 0
UNIQUE_PAGES = set()
WORD_FREQ = {}

MAX_PAGE_SIZE = 5_000_000
MIN_TEXT_LEN = 50
STOP_WORDS = {
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

ALLOWED_SUFFIXES = ("ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu")
ICS_SUBDOMAIN_BLACKLIST = {"ngs.ics.uci.edu", "grape.ics.uci.edu", "intranet.ics.uci.edu"} 

BLACKLIST_KEYWORDS = {
    "wics", "calendar", "ical", "tribe", "doku", "eppstein", "/events", "~eppstein/pix", "gallery", "action=diff", "action=edit", "share=", "print=", "format=pdf", "rev=", "do=media"
}
CALENDAR_TRAPS = re.compile(
    r"/(20[0-4][0-9]|19[7-9][0-9])"
    r"(/(0?[1-9]|1[0-2])"
    r"(/(0?[1-9]|[12][0-9]|3[01]))?)?"
)

BAD_EXT_RE = re.compile(
    r".*\.(css|js|bmp|gif|jpe?g|ico"
    r"|png|tiff?|mid|mp2|mp3|mp4"
    r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
    r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
    r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
    r"|epub|dll|cnf|tgz|sha1"
    r"|thmx|mso|arff|rtf|jar|csv"
    r"|rm|smil|wmv|swf|wma|zip|rar|gz)$",
    re.IGNORECASE
)

def scraper(url, resp):
    global TOTAL_VISITED

    if resp is None or resp.status != 200:
        return []

    TOTAL_VISITED += 1

    # Use final fetched URL and defragment it
    final_url = resp.url if getattr(resp, "url", None) else url
    final_url, _ = urldefrag(final_url)

    first_time = False
    if final_url not in UNIQUE_PAGES:
        UNIQUE_PAGES.add(final_url)
        first_time = True

        # Count subdomain only for unique crawled pages
        host = (urlparse(final_url).hostname or "").lower()
        if host:
            _count_subdomain(host, final_url)

    links = extract_next_links(final_url, resp, count_text=first_time)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp, count_text=False):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    if resp is None or resp.status != 200 or resp.raw_response is None:
        return []

    content = getattr(resp.raw_response, "content", None)
    if not content:
        return []

    if len(content) > MAX_PAGE_SIZE:
        return []

    content_type = resp.raw_response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type:
        return []

    links = []
    try:
        soup = BeautifulSoup(content, "lxml")

        base_url = resp.url if getattr(resp, "url", None) else url
        base_url, _ = urldefrag(base_url)

        # Extract <a href=...>
        for tag in soup.find_all("a", href=True):
            raw_href = tag.get("href")
            if not raw_href:
                continue
            raw_href = raw_href.strip()
            if not raw_href:
                continue

            absolute = urljoin(base_url, raw_href)
            absolute, _ = urldefrag(absolute)
            links.append(absolute)

        # Text stats (only for unique pages)
        if count_text:
            text = soup.get_text(separator=" ", strip=True)
            if len(text) >= MIN_TEXT_LEN:
                # LONGEST PAGE
                word_count = len(text.split())
                global LONGEST_PAGE
                if word_count > LONGEST_PAGE[1]:
                    LONGEST_PAGE = (base_url, word_count)

                # TOP WORDS (ignore stop words)
                words = re.findall(r"[a-zA-Z]{2,}", text.lower())
                for w in words:
                    if w in STOP_WORDS:
                        continue
                    WORD_FREQ[w] = WORD_FREQ.get(w, 0) + 1

                

    except Exception as e:
        print("error in extract_next_links:", e)

    return links

def _host_allowed(host: str) -> bool:
    host = host.lower()
    for suffix in ALLOWED_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False

def _count_subdomain(host: str, url: str):
    # Count unique crawled pages per subdomain under uci.edu.
    if not _host_allowed(host):
        return

    seen_set = COUNTED_PER_SUBDOMAIN.get(host)
    if seen_set is None:
        seen_set = set()
        COUNTED_PER_SUBDOMAIN[host] = seen_set

    if url not in seen_set:
        seen_set.add(url)
        SUBDOMAIN_COUNTS[host] = SUBDOMAIN_COUNTS.get(host, 0) + 1

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        host = (parsed.hostname or "").lower()
        if not host:
            return False

        # Domain restriction
        if not _host_allowed(host):
            return False

        # Block known-bad subdomains
        if host in ICS_SUBDOMAIN_BLACKLIST:
            return False

        # Block obvious login/admin
        if "wp-login.php" in parsed.path.lower():
            return False

        # Block non-html resources by extension
        if BAD_EXT_RE.match(parsed.path.lower()):
            return False

        lower_url = url.lower()

        # Keyword blacklist
        for bad in BLACKLIST_KEYWORDS:
            if bad in lower_url:
                return False

        # DokuWiki traps
        if "doku.php" in parsed.path.lower():
            return False

        # Events/calendar-ish trap paths
        if re.search(r"/events(\b|/|$)", lower_url):
            return False

        # Query trap heuristics (prevents tab_files/tab_details/do=image loops)
        qs = parse_qs(parsed.query)
        if len(qs) > 6:
            return False
        bad_q_keys = {"do", "tab_files", "tab_details", "image", "ns", "sectok"}
        if any(k.lower() in bad_q_keys for k in qs.keys()):
            return False

        # Calendar trap: date-based deep paths
        path = parsed.path.lower()
        if CALENDAR_TRAPS.search(path) and path.count("/") > 4:
            return False

        # Repeating segment heuristic
        if re.search(r"/(.+/)\1", path):
            return False

        # Path depth limit
        if path.count("/") > 12:
            return False

        # Super long URLs are often traps
        if len(url) > 300:
            return False

        return True

    except Exception:
        return False

def _print_report():
    print("\n========== CRAWL REPORT ==========")

    # 1) Unique pages
    print(f"Unique pages (defragmented): {len(UNIQUE_PAGES)}")

    # 2) Longest page
    print(f"Longest page by word count: {LONGEST_PAGE[0]} ({LONGEST_PAGE[1]} words)")

    # 3) Top 50 words
    top50 = sorted(WORD_FREQ.items(), key=lambda x: (-x[1], x[0]))[:50]
    print("\nTop 50 words (stopwords removed):")
    for w, c in top50:
        print(f"{w}: {c}")

    # 4) Subdomains
    print("\nSubdomains in uci.edu (alphabetical):")
    for host in sorted(SUBDOMAIN_COUNTS.keys()):
        print(f"{host}, {SUBDOMAIN_COUNTS[host]}")

    print("==================================\n")

atexit.register(_print_report)
