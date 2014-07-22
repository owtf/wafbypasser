import urlparse
from copy import copy
from time import time


class HTTPHelper:

    def __init__(self, init_request):
        # relates a payload with an http request. Needed for async fuzzing.
        # variable schema payload_table[id(request)] = payload
        self.payload_table = {}
        self.init_request = init_request

    def create_http_request(self, method, url, body=None, headers=None,
                            payload=None):
        """This function creates an HTTP request with some additional
         initializations"""

        request = copy(self.init_request)
        request.method = method
        request.url = url
        if body:
            request.body = body
        if headers:
            request.headers = headers
        request.start_time = time()
        if payload:
            self.payload_table[id(request)] = payload
        return request

    def get_payload_table(self):
        return self.payload_table

    def get_payload(self, response):
        return self.payload_table[id(response.request)]

    @staticmethod
    def add_url_param(url, param_name, param_value):
        if urlparse.urlparse(url)[4] == '':
            sep = "?"
        else:
            sep = '&'
        url += sep + param_name + "=" + param_value
        return url

    @staticmethod
    def add_body_param(body, param_name, param_value):
        if body is None or body == '':
            sep = ""
        else:
            sep = '&'
        body += sep + param_name + "=" + param_value
        return body

    @staticmethod
    def add_cookie_param(headers, param_name, param_value):
        new_headers = headers.copy()
        try:
            cookie_value = new_headers.pop('Cookie')
            sep = "&"
        except KeyError:
            cookie_value = ""
            sep = ""
        cookie_value += sep + param_name + "=" + param_value
        new_headers.add("Cookie", cookie_value)
        return new_headers

    @staticmethod
    def add_header_param(headers, param_name, param_value):
        new_headers = headers.copy()
        new_headers.pop(param_name)
        new_headers.add(param_name, param_value)
        return new_headers