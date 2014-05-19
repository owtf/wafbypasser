from tornado import ioloop
from tornado.httpclient import *
import urlparse
import urllib
from tornado.httputil import *
import os
import argparse
from tornado.httputil import HTTPHeaders
# My example:
#curl 'http://target.com/?get_var=get_value' --data 'post_var=post_value' --cookie 'cookie_name=cookie_value'
#curl 'http://target.com/?get_var=@@@FUZZ_HERE@@@' --data 'post_var=@@@FUZZ_HERE@@@' --cookie 'cookie_name=@@@FUZZ_HERE@@@'
#curl 'http://target.com/?@@@FUZZ_HERE@@@=get_value' --data '@@@FUZZ_HERE@@@=post_value' --cookie '@@@FUZZ_HERE@@@=cookie_value'
#curl 'http://target.com/@@@FUZZ_HERE@@@/?get_var=get_value' --data 'post_var=post_value' --cookie 'cookie_name=cookie_value'
#curl 'http://target.com/@@@FUZZ_HERE@@@/?get_var=get_value' --data 'post_var={"this" : "is", "json" : "@@@FUZZ_PLACEHOLDER@@@"}' --cookie 'cookie_name=cookie_value'


class Fuzzer:

    def __init__(self):
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64)" + \
         "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + \
         "34.0.1847.132 Safari/537.36"
        self.auth_username = None
        self.auth_password = None
        self.follow_redirects = True
        self.gzip = True
        self.max_redirects = 10
        self.allow_nonstandard_methods = True
        self.validate_cert = False
        self.headers = None
        #####
        ##The proxy data would be initialized with the OWTD MiTM proxy values
        self.proxy_host = None
        self.proxy_port = None
        self.proxy_username = None
        self.proxy_password = None
        #####
        self.req_counter = 0
        #####
        self.fsig = "@fuzzme@"  # fuzzing signature
        #self.detection_methods = [
        # self.contains,
        # self.resp_code_detection]
        #Available Detection Methods
        self.detection_methods = {}
        self.detection_methods["contains"] = self.contains
        self.detection_methods["response_code"] = self.resp_code_detection

    #This function is has as input :
    #1)the packets to send async
    #2)A reference to a method that will detect if a response is what we are
    #searching for
    #3)The Argmuments for the detection function
    def fuzz(self, packets, detection_method, detection_args):
        ''' This is the asyncrhonous fuzzing engine.'''
        http_client = AsyncHTTPClient()
        self.req_num = len(packets)  # number of sending requests
        self.responses = 0  # this is used for counting the responces
        for i in range(0, len(packets)):
            http_client.fetch(
                packets[i],
                #lambda is used for passing arguments to the callback function
                lambda response: self.handle_response(
                    response,
                    detection_method,  # referece to function
                    detection_args))
        ioloop.IOLoop.instance().start()

    def handle_response(self, response, detection_method, detection_args):
        '''This a callback function which handles the http responces.
        Is called by the fuzz function.'''
        #print response.request.url
        #if response.error:
        if detection_method(response, detection_args):
            self.log(response)
        #print response.request.url
        self.responses += 1
        if self.responses == self.req_num:  # if this is the last response
            ioloop.IOLoop.instance().stop()

    #
    def create_GET_requests(self, url, payloads, headers=None):
        """This function returns a list of GET requests which contain the
        payload"""
        requests = []
        fuzzing_url = False
        new_url = url
        new_headers = headers
        if url.find(self.fsig) > -1:  # check if we are fuzzing url or headers
            fuzzing_url = True
        else:  # Fuzzing headers
            nf_headers = HTTPHeaders()  # non fuzzing headers
            #here is searching for headers that needs to be fuzzed
            for i in range(0, len(headers.keys())):
                header_name_pos = headers.keys()[i].find(self.fsig)
                header_value_pos = headers[headers.keys()[i]].find(self.fsig)
                #if header does not contains the fuzzing singature
                if header_name_pos == -1 and header_value_pos == -1:
                    nf_headers.add(
                        headers.keys()[i],
                        headers[headers.keys()[i]]
                                    )
                else:
                    key = headers.keys()[i]
                    value = headers[headers.keys()[i]]
                    #if header_name_pos > -1:
        for i in range(0, len(payloads)):
            if fuzzing_url:
                new_url = url.replace(self.fsig, urllib.quote_plus(payloads[i]))
            else:  # fuzzing headers
                #print nf_headers.keys()
                new_headers = nf_headers.copy()
                new_headers.add(key.replace(self.fsig, payloads[i]),
                    value.replace(self.fsig, payloads[i])
                    )
            requests.append(self.createHTTPrequest(
                "GET",
                 new_url,
                 None,  # no body for GET requests
                 new_headers))
        return requests

    def create_POST_requests(self, url, payloads, body, headers=None):
        """This function returns a list of POST requests which contain the
        payload"""
        requests = []
        fuzzing_url = False
        fuzzing_body = False
        new_body = body
        new_url = url
        new_headers = headers
        if url.find(self.fsig) > -1:  # check if we are fuzzing url or headers
            fuzzing_url = True
        elif body.find(self.fsig) > -1:
            fuzzing_body = True
        else:
            nf_headers = HTTPHeaders()

            #here is searching for headers that needs to be fuzzed
            for i in range(0, len(headers.keys())):
                header_name_pos = headers.keys()[i].find(self.fsig)
                header_value_pos = headers[headers.keys()[i]].find(self.fsig)
                #print header_name_pos
                if header_name_pos == -1 and header_value_pos == -1:
                    nf_headers.add(
                        headers.keys()[i],
                        headers[headers.keys()[i]]
                                    )
                else:
                    key = headers.keys()[i]
                    value = headers[headers.keys()[i]]
                    #if header_name_pos > -1:
        for i in range(0, len(payloads)):
            if fuzzing_url:
                new_url = url.replace(self.fsig, urllib.quote_plus(payloads[i]))
            elif fuzzing_body:
                new_body = body.replace(self. fsig,
                      urllib.quote_plus(payloads[i]))
            else:  # fuzzing headers
                #print nf_headers.keys()
                new_headers = nf_headers.copy()
                new_headers.add(key.replace(self.fsig, payloads[i]),
                    value.replace(self.fsig, payloads[i])
                    )
            #add the new request to the list
            requests.append(self.createHTTPrequest(
                "POST",
                 new_url,
                 new_body,
                 new_headers))
        return requests

    def createHTTPrequest(self, method, url, body=None, headers=None):
        """This function creates an HTTP request whith some additional
         initialiazations"""
        return HTTPRequest(
                    url=url,
                    method=method,
                    headers=headers,
                    body=body,
                    #user_agent=self.user_agent,
                    follow_redirects=self.follow_redirects,
                    #use_gzip=self.gzip,
                    proxy_host=self.proxy_host,
                    proxy_port=self.proxy_port,
                    proxy_username=self.proxy_username,
                    proxy_password=self.proxy_password,
                    max_redirects=self.max_redirects,
                    allow_nonstandard_methods=self.allow_nonstandard_methods,
                    validate_cert=self.validate_cert,
                    )

    def load_payload_file(self, payload_path, valid_size=100000, exclude_chars=[]):
        """This Function loads a list with payloads"""
        try:
            file_handle = open(os.path.expanduser(payload_path), "r")
        except IOError as e:
            self.Error(str(e))
        payloads = []
        file_buf = file_handle.read()

        lines = file_buf.split("\n")
        for line in lines:
            if len(str(line)) <= valid_size:
                valid = True
                for i in range(0, len(exclude_chars)):
                    if str(line).find(exclude_chars[i]) > -1:
                        valid = False
                        break
                if valid:
                    payloads.append(str(line))
        print "Payload: " + str(payload_path) + " Loaded."
        file_handle.close()
        return payloads

    def log(self, response):  # Not implemented yet
        print "/^^^^^^^^^^^^^^^^^^^^^^^^^^^\\"
        print "Something Interesting Found"
        print " --------------------------- "
        print "Request URL:"
        print response.request.url
        print "Request Headers :"
        print response.request.headers

        if response.request.body is not None:
            print "Request body:"
            print response.request.body
        print "\----------------------------/"
        print

#################Detection-Methods####################
#Each detection method takes as input an HTTP request and a list with extra args
    def contains(self, response, args):
        """This function detected if the body of an http responce contains a
        specific string"""
        phrase = args[0]  # string to search for in HTTP request body.
        if len(args) == 2:
            case_sensitive = args[1]  # this is a True False flag
        else:
            case_sensitive = False
        body = response.body
        if body is None:
            if len(phrase) == 0:
                return True
            else:
                return False
        if not case_sensitive:
            phrase = phrase.lower()
            body = body.lower()
        if body.find(phrase) > -1:
                return True
        return False

# Args
#Ex 200-300,402,404
    def resp_code_detection(self, response, args):
        code_range = []
        items = args[0].split(",")
        for i in range(0, len(items)):
            tokens = items[i].split("-")
            if len(tokens) == 2:
                #for j in range(int(tokens[0]), int(tokens[1])):
                    #code_range.append(j)
                code_range.extend(range(int(tokens[0]), int(tokens[1]) + 1))
            else:
                code_range.append(int(tokens[0]))
        #print code_range
        #print response.code
        if response.code in code_range:
            return True
        else:
            return False

    def GetArgs(self):
        parser = argparse.ArgumentParser(description='OWTF WAF-BYPASER MODULE')
        parser.add_argument("-C", "--cookie",
                        dest="COOKIE",
                        action='store',
                        help="Insert a cookie value. (ex --cookie 'var=value')")
        parser.add_argument("-t", "--target",
                        dest="TARGET",
                        action='store',
                        required=True,
                        help="The target url")
        parser.add_argument("-H", "--headers",
                        dest="HEADERS",
                        action='store',
                        nargs='*',
                        help="Additional headers (ex -header 'Name:value' 'Name2:value2')")
        #parser.add_argument("-S", "--size",
        #                dest="SIZE",
        #                action='store',
        #                help="GET the size of a variable")
        parser.add_argument("-p", "--data",
                        dest="DATA",
                        action='store',
                        help="POST data (ex --data 'var=value')")
        parser.add_argument("-d", "--detection_method",
                        dest="DETECTION_METHOD",
                        action='store',
                        nargs='+',
                        required=True,
                        help="DETECTION METHOD(ex -d contains 'signature')\n" +
                        "Detection Methods:" +
                        str(self.detection_methods.keys()))
        parser.add_argument("-pl", "--payloads",
                        dest="PAYLOADS",
                        action='store',
                        nargs='*',
                        required=True,
                        help="FILE with payloads')(Ex file1 , file2)")
        return parser.parse_args()

    def Error(self, message):
        print "Error:" + message
        exit(-1)

    def Start(self, Args):
        if str(Args).count(self.fsig) > 1:
            self.Error("Multiple Fuzzing signatures found.\nOnly one" +
                       " fuzzing placeholder id supported.")

        headers = HTTPHeaders()
        method = "GET"
        if Args.TARGET:
            target = Args.TARGET
        if Args.COOKIE:
            headers.add("Cookie", Args.COOKIE)
        if Args.HEADERS:
            for i in range(0, len(Args.HEADERS)):
                values = Args.HEADERS[i].split(":")
                headers.add(values[0], values[1])
        if Args.DATA:
            method = "POST"
            data = Args.DATA
        if Args.DETECTION_METHOD:
            #if Args.DETECTION_METHOD[0] == "contains":
                #detection_method = self.contains
            detection_method = self.detection_methods[Args.DETECTION_METHOD[0]]
            #elif
            detection_args = []
            detection_args = Args.DETECTION_METHOD[1:]
#            for i in range(1, len(Args.DETECTION_METHOD)
#                detection_args.append(Args.DETECTION_METHOD[i])
        if Args.PAYLOADS:
            payloads = []
            for i in range(0, len(Args.PAYLOADS)):
                payloads += self.load_payload_file(Args.PAYLOADS[i])
        if method == "GET":
            requests = self.create_GET_requests(target, payloads, headers)
        else:  # Post Packets
            requests = self.create_POST_requests(
                target,
                payloads,
                data,
                headers)

        self.fuzz(requests, detection_method, detection_args)

if __name__ == "__main__":
    #Banner()
    fuzzer = Fuzzer()
    arguments = fuzzer.GetArgs()
    fuzzer.Start(arguments)

