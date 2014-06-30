from urllib2 import *
from base64 import *


def get_transformations():
    return {
        "base64": base64,
        "urlsafe_base64": urlsafe_base64,
        "hex": hex,
        "remove_spaces": remove_spaces,
        "urlencode": urlencode,
        "xmlcharrefreplace": xmlcharrefreplace,
        "html_escape": html_escape,
        "utf8": utf8,
        "utf16": utf16,
        "utf32": utf32,
        "replace": replace,
        "reverse": reverse,
        "remove_newlines": remove_newlines,
        "remove_spaces": remove_spaces
    }


def base64(string):
    return standard_b64encode(string)


def urlsafe_base64(string):
    return urlsafe_b64encode(string)


def hex(string):
    return string.encode("hex")


def remove_spaces(string):
    return string.replace(" ", "")


def urlencode(string):
    return quote(string)


def xmlcharrefreplace(string):
    return string.encode('ascii', 'xmlcharrefreplace')


html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
}


# credits https://wiki.python.org/moin/EscapingHtml
def html_escape(text):
    """Produce entities within text."""
    return "".join(html_escape_table.get(c, c) for c in text)


def utf8(string):
    return string.encode('utf-8')


def utf16(string):
    return string.encode('utf-16')


def utf32(string):
    return string.encode('utf-32')


def replace(string, old, new):
    return string.replace(old, new)


def reverse(string):
    return string[::-1]


def remove_newlines(string):
    string = string.replace("\n", "");
    return string.replace("\r", "")


def remove_spaces(string):
    return string.replace(" ", "")
