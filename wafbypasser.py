#!/bin/python
from tornado.httputil import HTTPHeaders
from tornado.httpclient import HTTPRequest

from core.hpp_lib import asp_hpp
from core.placeholder_length import find_length
from core.detection import *
from core.argument_parser import get_args
from core.fuzzer import Fuzzer
from core.helper import load_payload_file, Error
from core.http_helper import HTTPHelper
from core.param_source_detector import detect_accepted_sources
from core.response_analyzer import analyze_responses
from core.placeholder_manager import PlaceholderManager



class WAFBypasser:
    def __init__(self):
        self.ua = "Mozilla/5.0 (X11; Linux i686; rv:6.0) Gecko/20100101 /" \
                  "Firefox/15.0"

        self.init_request = HTTPRequest("",
                                        auth_username=None,
                                        auth_password=None,
                                        follow_redirects=True,
                                        max_redirects=10,
                                        allow_nonstandard_methods=True,
                                        headers=None,
                                        proxy_host=None,
                                        proxy_port=None,
                                        proxy_username=None,
                                        proxy_password=None,
                                        user_agent=self.ua,
                                        request_timeout=30.0)
        # ####
        self.sig = "@@@"
        self.lsig = self.sig + "length" + self.sig  # Length Signature
        self.fsig = self.sig + "fuzzhere" + self.sig  # fuzzing signature
        # template signature regular expression
        self.template_signature_re = self.sig +\
                                     "[^" + self.sig + "]+" + self.sig
        # ####
        self.detection_struct = []
        self.requests_table = {}
        self.http_helper = None


    def start(self, Args):
        if Args.FUZZING_SIG:
            self.sig = Args.FUZZING_SIG
        if PlaceholderManager.get_placeholder_number(
                self.template_signature_re, str(Args)) > 1:
            Error("Multiple fuzzing placeholder signatures found."\
                  " Only one fuzzing placeholder is supported.")

        methods = Args.METHOD
        if methods:
            for method in methods:
                if method == "@method@":
                    methods.remove(method)
                    methods.extend(
                        load_payload_file(
                            "./payloads/HTTPmethods/methods.txt"))
                    methods = list(set(methods))  # Removing doubles
                    break
        else:
            methods = []
            if Args.DATA is None:
                methods.append("GET")  # Autodetect Method
            else:
                methods.append("POST")  # Autodetect Method

        if Args.DATA:
            data = Args.DATA
        else:
            data = ""

        if Args.TARGET:
            target = Args.TARGET

        headers = HTTPHeaders()
        if Args.COOKIE:
            headers.add("Cookie", Args.COOKIE)
        if Args.HEADERS:
            for header in Args.HEADERS:
                values = header.split(':', 1)
                if len(values) == 2:
                    headers.add(*values)
                else:  # values == 1
                    headers.add(values[0], "")

        if Args.CONTAINS is None and Args.RESP_CODE_DET is None:
            Error("You need to specify a detection method")

        if Args.CONTAINS:
            detection_args = {}
            detection_args["phrase"] = Args.CONTAINS[0]  # detection string
            detection_args["case_sensitive"] = "cs" in Args.CONTAINS[1:]
            detection_args["reverse"] = False
            if Args.REVERSE:
                detection_args["reverse"] = True
            self.detection_struct.append({"method": contains,
                                          "arguments": detection_args,
                                          "info": "Contains"})
        if Args.RESP_CODE_DET:
            detection_args = {}
            detection_args["response_codes"] = Args.RESP_CODE_DET[0]
            detection_args["reverse"] = False
            if Args.REVERSE:
                detection_args["reverse"] = True
            self.detection_struct.append({"method": resp_code_detection,
                                          "arguments": detection_args,
                                          "info": "Contains"})

        self.http_helper = HTTPHelper(self.init_request)
        if Args.LENGTH:
            print "Scanning mode: Length Detection"
            ch = Args.LENGTH[0][0]

            length = find_length(self.http_helper,
                                 self.lsig,
                                 target,
                                 methods[0],
                                 self.detection_struct,
                                 ch,
                                 headers,
                                 None)
            print "Allowed Length = " + str(length)

        elif Args.DETECT_ALLOWED_SOURCES:
            print "Scanning mode: Allowed Sources Detection"
            accepted_method = Args.ACCEPTED_METHOD
            param_name = Args.PARAM_NAME
            param_value = Args.ACCEPTED_PARAM_VALUE
            param_source = Args.PARAM_SOURCE

            if accepted_method is None:
                Error("--accepted_method is not specified.")
            if param_name is None:
                Error("--param_name is not specified.")
            if param_value is None:
                Error("--param_value is not specified.")
            if param_source is None:
                Error("--param_source is not specified.")

            methods = load_payload_file("./payloads/HTTP/methods.txt")
            requests = detect_accepted_sources(self.http_helper,
                                               target,
                                               data,
                                               headers,
                                               param_name,
                                               param_source,
                                               param_value,
                                               methods,
                                               accepted_method)
        else:
            if Args.PAYLOADS:
                payloads = []
                for payload in Args.PAYLOADS:
                    payloads += load_payload_file(payload)
            else:
                Error("Payloads not Specified")
            # HPP check
            hpp_attacking_method = Args.HPP_ATTACKING_METHOD
            if hpp_attacking_method:
                print "Scanning mode: HTTP Parameter Pollution Mode"
                if hpp_attacking_method.upper() == "ASP":
                    # ASP HPP code
                    source = Args.HPP_SOURCE
                    param_name = Args.HPP_PARAM_NAME
                    if source is None:
                        Error("--hpp_source is not specified")
                    elif param_name is None:
                        Error("--param_name is not specified")
                    else:
                        requests = asp_hpp(self,
                                           methods,
                                           payloads,
                                           param_name,
                                           source,
                                           target,
                                           headers,
                                           data)

            else:  # Fuzzing using content placeholders loaded from file
                print "Scanning mode: Fuzzing Using placeholders"
                pm = PlaceholderManager(self.sig)
                if Args.CONTENT_TYPE:
                    content_type_list = load_payload_file(
                        "./payloads/HTTP/content_types.txt")
                else:
                    content_type_list = None
                requests = pm.transformed_http_requests(
                    self.http_helper,
                    methods,
                    target,
                    payloads,
                    headers,
                    data,
                    content_type_list)

        if not Args.LENGTH:
            print "Requests number: " + str(len(requests))
            fuzzer = Fuzzer(self.http_helper)
            delay = Args.DELAY
            follow_cookies = Args.FOLLOW_COOKIES
            if follow_cookies or delay:
                print "Synchronous Fuzzing: Started"
                responses = fuzzer.sync_fuzz(requests ,delay, follow_cookies)
            else:
                print "ASynchronous Fuzzing: Started"
                responses = fuzzer.async_fuzz(requests)
            print "Fuzzing: Completed"
            analyze_responses(responses,
                              self.http_helper,
                              self.detection_struct)


if __name__ == "__main__":
    wafbypasser = WAFBypasser()
    arguments = get_args()
    wafbypasser.start(arguments)
