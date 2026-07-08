AUTHOR = "Argus"
SITENAME = "The Drift Corpus: Ring 0"
SITESUBTITLE = "Diff work corpus browser"
SITEURL = ""

PATH = "content"
ARTICLE_PATHS = ["posts"]
STATIC_PATHS = []

TIMEZONE = "America/Los_Angeles"
DEFAULT_LANG = "en"

# Use the exact same theme as argus-blog.
THEME = "themes/argus"

ARTICLE_URL = "item/{slug}.html"
ARTICLE_SAVE_AS = "item/{slug}.html"
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "none": 0}


def ARTICLE_ORDER_BY(article):
    # Highest severity first, then newest date first within the same severity.
    sev = (getattr(article, "severity", "none") or "none").strip().lower()
    return (-_SEV_RANK.get(sev, 0), -article.date.toordinal())
DEFAULT_DATE_FORMAT = "%Y-%m-%d"

FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

LINKS = (
    ("Home", "/"),
)

SOCIAL = ()
DEFAULT_PAGINATION = 50
