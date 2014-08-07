#!/bin/python
from tornado.httputil import HTTPHeaders
from tornado.httpclient import HTTPRequest

from core.hpp_lib import asp_hpp, param_overwrite
from core.placeholder_length import find_length
from core.detection import *
from core.argument_parser import get_args
from core.fuzzer import Fuzzer
from core.helper import load_payload_file, Error
from core.http_helper import HTTPHelper
from core.param_source_detector import detect_accepted_sources
from core.response_analyzer import analyze_responses, print_request, print_response, analyze_chars, analyze_encoded_chars
from core.placeholder_manager import PlaceholderManager
from core.obfuscation_lib import unicode_urlencode, urlencode
import string


class WAFBypasser:

    def fuzz(self, args, requests):
        if args["follow_cookies"] or args["delay"]:
            delay = args["delay"] or 0
            follow_cookies = args["follow_cookies"] or False
            print "Synchronous Fuzzing: Started"
            responses = self.fuzzer.sync_fuzz(requests, delay, follow_cookies)
        else:
            print "Requests number: " + str(len(requests))
            print "Asynchronous Fuzzing: Started"
            responses = self.fuzzer.async_fuzz(requests)
        print "Fuzzing: Completed"
        return responses


    def is_detection_set(self, args):
        if args["contains"] is None and args["resp_code_det"] is None:
            Error("You need to specify at least on Detection Function.")


    def require(self, args, params):
        param_missing = False
        for param in params:
            if param is None:
                param_missing = True
                print "Specify: --" + param
        if param_missing:
            Error("Missing Parameter(s).")


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
        self.length_signature = self.sig + "length" + self.sig
        self.fsig = self.sig + "fuzzhere" + self.sig  # fuzzing signature
        # template signature regular expression
        self.template_signature_re = self.sig + \
                                     "[^" + self.sig + "]+" + self.sig
        # ####
        self.detection_struct = []
        self.pm = None
        #self.http_helper = HTTPHelper(self.init_request)
        #self.fuzzer = Fuzzer(self.http_helper)
        #self.args =  FIXME


    def init_methods(self, args):
        methods = args["methods"] or []
        # Setting Methods
        if methods:
            if self.sig + "all" + self.sig in methods:
                methods.remove(self.sig + "all" + self.sig)
                methods.extend(
                    load_payload_file("./payloads/HTTP/methods.txt"))
                methods = list(set(methods))  # Removing doublesk
        else:
            if args["data"] is None:
                methods.append("GET")  # Autodetect Method
            else:
                methods.append("POST")  # Autodetect Method
        return methods


    def init_headers(self, args):
        headers = HTTPHeaders()
        if args["headers"]:
            for header in args["headers"]:
                values = header.split(':', 1)
                if len(values) == 2:
                    headers.add(*values)
                else:  # values == 1
                    headers.add(values[0], "")
        # Setting Cookies
        if args["cookie"]:
            headers.add("Cookie", args["cookie"])
        return headers


    def init_detection_struct(self, args):
        if args["contains"]:
            detection_args = {}
            detection_args["phrase"] = args["contains"][0]  # detection string
            detection_args["case_sensitive"] = "cs" in args["contains"][1:]
            detection_args["reverse"] = False
            if args["reverse"]:
                detection_args["reverse"] = True
            self.detection_struct.append({"method": contains,
                                          "arguments": detection_args,
                                          "info": "Contains"})
        if args["resp_code_det"]:
            detection_args = {}
            detection_args["response_codes"] = args["resp_code_det"][0]
            detection_args["reverse"] = False
            if args["reverse"]:
                detection_args["reverse"] = True
            self.detection_struct.append({"method": resp_code_detection,
                                          "arguments": detection_args,
                                          "info": "Contains"})


    def start(self, args):
        # Initiliazations
        self.sig = args["fuzzing_signature"] or self.sig
        self.pm = PlaceholderManager(self.sig)
        target = args["target"]
        methods = self.init_methods(args)
        headers = self.init_headers(args)
        data = args["data"] or ""
        self.init_detection_struct(args)
        self.init_request.headers=headers
        self.http_helper = HTTPHelper(self.init_request)
        self.fuzzer = Fuzzer(self.http_helper)



        #FIXME allow only one mode
        # Available Testing Modes
        #
        # Finding the length of a placeholder
        if args["length"]:
            self.is_detection_set(args)
            if len(methods) > 1:
                Error("Only you need to specify only one Method")
            print "Scanning mode: Length Detection"
            ch = args["length"][0][0]
            length = find_length(self.http_helper,
                                 self.length_signature,
                                 target,
                                 methods[0],
                                 self.detection_struct,
                                 ch,
                                 headers,
                                 data)
            print "Placeholder Allowed Length = " + str(length)
        # Detecting Allowed Sources
        elif args["detect_allowed_sources"]:
            self.require(args, ["method",
                                "param_name",
                                "accepted_value",
                                "param_source"])

            if len(methods) > 1:
                Error("Only you need to specify only one Method")
            print "Scanning mode: Allowed Sources Detection"

            accepted_method = methods[0]
            param_name = args["param_name"]
            accepted_value = args["accepted_value"]
            param_source = args["param_source"]
            methods = load_payload_file("./payloads/HTTP/methods.txt")
            requests = detect_accepted_sources(self.http_helper,
                                               target,
                                               data,
                                               headers,
                                               param_name,
                                               param_source,
                                               accepted_value,
                                               methods,
                                               accepted_method)
            # FIXME analyze requests
            responses = self.fuzz(args, requests)

        elif args["content_type"]:
            print "Tampering Content-Type mode"
            cnt_types = load_payload_file("./payloads/HTTP/content_types.txt")
            self.http_helper.add_header_param(headers,
                                              "Content-Type", self.fsig)
            self.pm = PlaceholderManager(self.sig)
            requests = self.pm.transformed_http_requests(
                self.http_helper,
                methods,
                target,
                cnt_types,
                headers,
                data)
            responses = self.fuzz(args, requests)
            for response in responses:
                print "Request"
                print_request(response)
                print "Response"
                print_response(response)
                print
        # HPP modes
        elif args["hpp"]:
            self.require(args, ["param_name", "param_source"])
            param_name = args["param_name"]
            accepted_source = args["param_source"]
            self.is_detection_set(args)

            if args["hpp"] == "asp":

                if args["payload"]:
                    payloads = load_payload_file(args["payload"])
                else:
                    load_payload_file("")  # FixMe add payloads from collection

                print "Scanning mode: ASP HPP Parameter Splitting"
                requests = asp_hpp(self.http_helper,
                                   methods,
                                   payloads,
                                   param_name,
                                   accepted_source,
                                   target,
                                   headers,
                                   data)
                responses = self.fuzz(args, requests)
                #fixme analyze the requests
            elif args["hpp"] == "parameter_overwriting":
                # FIXME Insert payload from stdin
                self.require(args, "payload")
                payloads = load_payload_file(args["payload"])
                requests = param_overwrite(self.http_helper,
                                           param_name,
                                           accepted_source,
                                           payloads[0],
                                           target,
                                           data,
                                           headers)
                responses = self.fuzz(args, requests)
                #fixme
        elif args["detect_allowed_chars"]:
            self.is_detection_set(args)
            payloads = []
            for i in range(0, 256):
                payloads.append(chr(i))

            requests = self.pm.transformed_http_requests(self.http_helper,
                                                     methods,
                                                     target,
                                                     payloads,
                                                     headers,
                                                     data)
            responses = self.fuzz(args, requests)
            sent_payloads = analyze_chars(responses,
                          self.http_helper,
                          self.detection_struct)
            payloads = []
            #urlencode bad_chars
            print
            print "URL encoding bad characters"
            for bad_char in sent_payloads["detected"]:
                payloads.append(urlencode(bad_char))
            requests = self.pm.transformed_http_requests(self.http_helper,
                                                     methods,
                                                     target,
                                                     payloads,
                                                     headers,
                                                     data)
            responses = self.fuzz(args, requests)
            analyze_encoded_chars(responses,
                          self.http_helper,
                          self.detection_struct)

            payloads = []
            #unicode_urlencode_badchars
            for bad_char in sent_payloads["detected"]:
                payloads.append(unicode_urlencode(bad_char))
            requests = self.pm.transformed_http_requests(self.http_helper,
                                                     methods,
                                                     target,
                                                     payloads,
                                                     headers,
                                                     data)
            responses = self.fuzz(args, requests)
            analyze_encoded_chars(responses,
                          self.http_helper,
                          self.detection_struct)

            payloads = []
            # add good char infront of bad char
            for bad_char in sent_payloads["detected"]:
                payloads.append(bad_char + sent_payloads["undetected"][0])
            requests = self.pm.transformed_http_requests(self.http_helper,
                                                     methods,
                                                     target,
                                                     payloads,
                                                     headers,
                                                     data)
            responses = self.fuzz(args, requests)
            analyze_encoded_chars(responses,
                          self.http_helper,
                          self.detection_struct)

            if sent_payloads["detected"] is not []:
                print
                print "Sending a detected char after an undetected"
                good_char = None
                for char in string.letters:
                    good_char = char
                    break
                if not good_char:
                    for char in string.digits:
                        good_char = char
                        break
                if not good_char:
                    good_char = sent_payloads["undetected"][0]
                payloads = []
                for bad_char in sent_payloads["detected"]:
                    payloads.append(good_char + bad_char)
                requests = self.pm.transformed_http_requests(self.http_helper,
                                                         methods,
                                                         target,
                                                         payloads,
                                                         headers,
                                                         data)
                responses = self.fuzz(args, requests)
                analyze_encoded_chars(responses,
                              self.http_helper,
                              self.detection_struct)

                print "Sending an undetected char after a detected"
                payloads = []
                for bad_char in sent_payloads["detected"]:
                    payloads.append(bad_char + good_char)
                requests = self.pm.transformed_http_requests(self.http_helper,
                                                         methods,
                                                         target,
                                                         payloads,
                                                         headers,
                                                         data)
                responses = self.fuzz(args, requests)
                analyze_encoded_chars(responses,
                              self.http_helper,
                              self.detection_struct)

                print "Sending an detected char surrounded by undetected chars"
                payloads = []
                for bad_char in sent_payloads["detected"]:
                    payloads.append(good_char + bad_char + good_char)
                requests = self.pm.transformed_http_requests(self.http_helper,
                                                         methods,
                                                         target,
                                                         payloads,
                                                         headers,
                                                         data)
                responses = self.fuzz(args, requests)
                analyze_encoded_chars(responses,
                              self.http_helper,
                              self.detection_struct)

        # Fuzzing mode
        elif args["fuzz"]:
            if PlaceholderManager.get_placeholder_number(
                    self.template_signature_re, str(args)) > 1:
                Error("Multiple fuzzing placeholder signatures found." \
                      " Only one fuzzing placeholder is supported.")

            self.is_detection_set(args)

            payloads = []
            if args["payloads"]:
                for payload in args.PAYLOADS:
                    payloads += load_payload_file(payload)
            else:
                pass
                # FIXME add Payloads from payload collection
                payloads.append("test")

            print "Scanning mode: Fuzzing Using placeholders"

            requests = self.pm.transformed_http_requests(self.http_helper,
                                                         methods,
                                                         target,
                                                         payloads,
                                                         headers,
                                                         data)
            responses = self.fuzz(args, requests)

            analyze_responses(responses,
                              self.http_helper,
                              self.detection_struct)


if __name__ == "__main__":
    wafbypasser = WAFBypasser()
    arguments = get_args()
    wafbypasser.start(arguments)
