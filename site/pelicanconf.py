AUTHOR = "Argus"
SITENAME = "Argus Drift Corpus"
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
ARTICLE_ORDER_BY = "reversed-date"
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
