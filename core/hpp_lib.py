import urlparse

# ##########################################  # ASP HPP Functions
#
# www.example.com?index.asp?<asp_hpp/ param_name=email >
# variable name
#   header, body or url
#   type of hpp
#   tokens
#   number of tokens (optional)
#  --hpp url,body,cookie param_name asp(optional)
#

def asp_hpp(wafbypasser, methods, payloads, param_name, source, url, headers, body=None):
    requests = []
    if "URL" in source.upper():
        for payload in payloads:
            new_url = asp_url_hpp(url, param_name, payload)
            for method in methods:
                requests.append(
                    wafbypasser.createHTTPrequest(
                        method,
                        new_url,
                        body,
                        headers,
                        payload
                    )
                )
    elif "DATA" in source.upper():
        for payload in payloads:
            new_body = asp_post_hpp(body, param_name, payload)
            for method in methods:
                requests.append(
                    wafbypasser.createHTTPrequest(
                        method,
                        url,
                        new_body,
                        headers,
                        payload))
    elif "COOKIE" in source.upper():
        for payload in payloads:
            new_headers = asp_cookie_hpp(headers, param_name, payload)
            for method in methods:
                requests.append(
                    wafbypasser.createHTTPrequest(
                        method,
                        url,
                        body,
                        new_headers,
                        payload))
    return requests


def asp_url_hpp(url, param_name, payload):
    if urlparse.urlparse(url)[4] == '':
        sep = "?"
    else:
        sep = '&'
    for pay_token in payload.split(","):
        url += sep + param_name + "=" + pay_token
        sep = '&'
    return url


def asp_post_hpp(body, param_name, payload):
    if body is None or body == '':
        sep = ""
    else:
        sep = '&'
    for pay_token in payload.split(","):
        body += sep + param_name + "=" + pay_token
        sep = '&'
    return body


def asp_cookie_hpp(headers, param_name, payload):
    new_headers = headers.copy()
    try:
        cookie_value = new_headers.pop('Cookie')
        sep = "&"
    except KeyError:
        cookie_value = ""
        sep = ""
    for pay_token in payload.split(","):
        cookie_value += sep + param_name + "=" + pay_token
        sep = '&'
    new_headers.add("Cookie", cookie_value)
    return new_headers