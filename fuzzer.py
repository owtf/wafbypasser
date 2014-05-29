from tornado import ioloop
from tornado.httpclient import *
import urlparse
import urllib
from tornado.httputil import *
import os
import argparse
from tornado.httputil import HTTPHeaders
import ast
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
        ##The proxy data would be initialized with the OWTF MiTM proxy values
        self.proxy_host = None
        self.proxy_port = None
        self.proxy_username = None
        self.proxy_password = None
        #####
        self.req_counter = 0
        #####
        self.lsig = "@length@"  # Length Signature
        self.fsig = "@fuzzme@"  # fuzzing signature
        #####
        self.detection_struct = []

    #This function is has as input :
    #1)the packets to send async
    #2)A reference to a method that will detect if a response is what we are
    #searching for
    #3)The Argmuments for the detection function
    def fuzz(self, packets, detection_struct):
        ''' This is the asynchronous fuzzing engine.'''
        http_client = AsyncHTTPClient()
        self.req_num = len(packets)  # number of sending requests
        self.responses = 0  # this is used for counting the responses
        for packet in packets:
            http_client.fetch(
                packet,
                #lambda is used for passing arguments to the callback function
                lambda response: self.handle_response(
                    response,
                    detection_struct))
        print "Status: Fuzzing Started"
        ioloop.IOLoop.instance().start()

    def handle_response(self, response, detection_struct):
        '''This a callback function which handles the http responses.
        Is called by the fuzz function.'''
        #print response.request.url
        #if response.error:
        for struct in detection_struct:
            if struct[1](response, struct[2]):
                self.log(struct[0], response)
                continue
        #print response.request.url
        self.responses += 1
        if self.responses == self.req_num:  # if this is the last response
            ioloop.IOLoop.instance().stop()
            print("Status: Fuzzing Completed")


    def create_GET_requests(self, url, payloads, headers=None):
        """This function returns a list of GET requests which contain the
        payload"""
        requests = []
        fuzzing_url = False
        new_url = url
        new_headers = headers
        key_found = ''
        value_found = ''
        if self.fsig in url:  # check if we are fuzzing url or headers
            fuzzing_url = True
        else:  # Fuzzing headers
            nf_headers = HTTPHeaders()  # non fuzzing headers
            #here is searching for headers that needs to be fuzzed
            for key, value in headers.items():
                header_name_pos = self.fsig in key
                header_value_pos = self.fsig in value
                #if header does not contains the fuzzing signature
                if not header_name_pos and not header_value_pos:
                    nf_headers.add(key, value)
                else:
                    key_found = key
                    value_found = value
                    #if header_name_pos > -1:
        for payload in payloads:
            if fuzzing_url:
                new_url = url.replace(self.fsig, urllib.quote_plus(payload))
            else:  # fuzzing headers
                #print nf_headers.keys()
                new_headers = nf_headers.copy()
                new_headers.add(
                    key_found.replace(self.fsig, payload),
                    value_found.replace(self.fsig, payload)
                )
            requests.append(
                self.createHTTPrequest(
                    "GET",
                    new_url,
                    None,  # no body for GET requests
                    new_headers)
            )
        return requests

    def create_POST_requests(self, url, payloads, body, headers=None):
        """This constructs a list of POST requests which contain the
        payload"""
        requests = []
        fuzzing_url = False
        fuzzing_body = False
        new_body = body
        new_url = url
        new_headers = headers
        key_found = ''
        value_found = ''
        if self.fsig in url:  # check if we are fuzzing url or headers
            fuzzing_url = True
        elif self.fsig in body:
            fuzzing_body = True
        else:
            nf_headers = HTTPHeaders()

            #here is searching for headers that needs to be fuzzed
            for key, value in headers.items():
                header_name_pos = self.fsig in key
                header_value_pos = self.fsig in value
                #print header_name_pos
                if not header_name_pos and not header_value_pos:
                    nf_headers.add(key, value)
                else:
                    key_found = key
                    value_found = value
                    #if header_name_pos > -1:
        for payload in payloads:
            if fuzzing_url:
                new_url = url.replace(self.fsig, urllib.quote_plus(payload))
            elif fuzzing_body:
                new_body = body.replace(self.fsig, urllib.quote_plus(payload))
            else:  # fuzzing headers
                #print nf_headers.keys()
                new_headers = nf_headers.copy()
                new_headers.add(
                    key_found.replace(self.fsig, payload),
                    value_found.replace(self.fsig, payload)
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

    ###################################################
    def find_length(self, url, method, detection_struct, ch, headers, body=None):
        #param_name = param.split("=", 1)[0]  # get the parameter name
        #size = 4096
        size = 8192
        minv = 0
        http_client = HTTPClient()

        new_url = url
        new_body = body
        new_headers = headers

        for loop in range(0, 15):  # used to avoid potensial deadloop
            payload = size * ch
            if self.lsig in url:
                new_url = url.replace(self.lsig, payload)  #warning urlencode and etc
            elif body is not None and self.lsig in body:
                new_body = body.replace(self.lsig, payload)
            elif headers is not None and self.lsig in str(headers):
                raw_val = str(headers)
                raw_val = raw_val.replace(self.lsig, payload)
                new_headers = ast.literal_eval(str(raw_val))
            else:
                self.Error("Length signature not found!")

            request = self.createHTTPrequest(method, new_url, new_body, new_headers)
            try:
                response = http_client.fetch(request)
                #print response.body
            except HTTPError as e:
                #print "Error:", e.code
                response = e.response

            for struct in detection_struct:
                if struct[1](response, struct[2]):
                    http_client.close()
                    return self.binary_search(minv, size, url, method, detection_struct, ch, headers, body)
            minv = size
            size = size * 2


    def mid_value(self, minv, maxv):
        return int((minv + maxv) / 2)

    def binary_search(self, minv, maxv, url, method, detection_struct, ch, headers, body=None):
        #self.counter += 1
        #print "counter = " +str(self.counter)
        mid = self.mid_value(minv, maxv)
        new_url = url
        new_body = body
        new_headers = headers

        if minv > maxv:
            return maxv

        http_client = HTTPClient()

        payload = ch * mid

        if self.lsig in url:
            new_url = url.replace(self.lsig, payload)  #warning urlencode and etc
        elif body is not None and self.lsig in body:
            new_body = body.replace(self.lsig, payload)
        elif headers is not None and self.lsig in headers:
            raw_val = str(headers)
            raw_val = raw_val.replace(self.lsig, payload)
            new_headers = ast.literal_eval(str(raw_val))

        request = self.createHTTPrequest(method, new_url, new_body, new_headers)
        try:
            response = http_client.fetch(request)
            #print response.body
        except HTTPError as e:
            #print "Error:", e.code
            response = e.response

        for struct in detection_struct:
            if struct[1](response, struct[2]):
                http_client.close()
                return self.binary_search(minv, mid - 1, url, method, detection_struct, ch, headers, body)
        http_client.close()
        return self.binary_search(mid + 1, maxv, url, method, detection_struct, ch, headers, body)


    def load_payload_file(self, payload_path, valid_size=100000, exclude_chars=[]):
        """This Function loads a list with payloads"""
        payloads = []
        try:
            with open(os.path.expanduser(payload_path), 'r') as f:
                for line in f.readlines():
                    line = line.strip('\n')
                    if len(line) > valid_size:
                        continue
                    excluded_found = [c in line for c in exclude_chars]
                    if True in excluded_found:
                        continue
                    payloads.append(line)
        except Exception as e:
            self.Error(str(e))
        print 'Payload: ' + payload_path + ' loaded.'
        print '\t' + str(len(payloads)) + ' payload(s) found.'
        return payloads

    def log(self, detection_method, response):  # Not implemented yet
        print "/^^^^^^^^^^^^^^^^^^^^^^^^^^^\\"
        print "Something Interesting Found"
        print "Detected with :" + detection_method
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

    #contains arguments
    #args[0] --> string to search for
    #args[1:] --> rev stands for reverse & cs stands for case sensitive
    def contains(self, response, args):
        """This function detected if the body of an http responce contains a
        specific string"""
        phrase = args[0]
        case_sensitive = False
        reverse = False
        try:
            case_sensitive = "cs" in args[1:]
        except IndexError:
            pass
        try:
            reverse = "rev" in args[1:]
        except IndexError:
            pass

        if response.body is None:
            if len(phrase) == 0:
                if reverse:
                    return False
                return True
            else:
                if reverse:
                    return True
                return False

        body = response.body
        if not case_sensitive:
            phrase = phrase.lower()
            body = body.lower()
        if phrase in body:
            if reverse:
                return False
            return True
        if reverse:
            return True
        return False

    # Args
    #Ex 200-300,402,404
    def resp_code_detection(self, response, args):
        code_range = []
        items = []
        reverse = False
        try:
            reverse = "rev" in args[1:]
        except IndexError:
            pass
        items = args[0].split(',')
        #try:
        #    items = args[0].split(',')
        #except IndexError:
        #    pass
        for item in items:
            tokens = item.split('-')
            if len(tokens) == 2:
                code_range.extend(range(int(tokens[0]), int(tokens[1]) + 1))
            else:
                code_range.append(int(tokens[0]))
        #print code_range
        #print response.code
        ret = response.code in code_range
        if reverse:
            return not ret
        return ret

    def GetArgs(self):
        parser = argparse.ArgumentParser(description='OWTF WAF-BYPASER MODULE')

        parser.add_argument("-X", "--request",
                            dest="METHOD",
                            action='store',
                            help="Specify Method . (ex -X GET)")
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
        parser.add_argument("-L", "--length",
                            dest="LENGTH",
                            action='store',
                            nargs=1,
                            help="Finds the Length of a content placeholder. " +
                                 "Parameter is a valid fuzzing character(ex -L 'A')")
        parser.add_argument("-p", "--data",
                            dest="DATA",
                            action='store',
                            help="POST data (ex --data 'var=value')")
        #Detection Methods Args
        parser.add_argument("-cnt", "--contains",
                            dest="CONTAINS",
                            action='store',
                            nargs='+',
                            help="DETECTION METHOD(ex1 -cnt 'signature'  \n)\n" +
                                 "Optional Arguments:\n" +
                                 "Case sensitive :\n" +
                                 "(ex2)-cnt 'signature' cs")
        parser.add_argument("-rcd", "--response_code",
                            dest="RESP_CODE_DET",
                            action='store',
                            nargs=1,
                            help="DETECTION METHOD(ex1 -rcd 200  \n)\n" +
                                 "(ex2 -rcd 400,404)+\n(ex3 rcd 200-400)\n)" +
                                 "(ex4 -rcd 100,200-300)")
        parser.add_argument("-r", "--reverse",
                            dest="REVERSE",
                            action='store_true',
                            help="Reverse the detection method.(Negative detection)")
        #Payload method Args
        parser.add_argument("-pl", "--payloads",
                            dest="PAYLOADS",
                            action='store',
                            nargs='*',
                            #required=True,
                            help="FILE with payloads')(Ex file1 , file2)")
        return parser.parse_args()

    def Error(self, message):
        print "Error: " + message
        exit(-1)

    def Start(self, Args):
        if str(Args).count(self.fsig) > 1:
            self.Error("Multiple Fuzzing signatures found.\nOnly one" +
                       " fuzzing placeholder is supported.")
        #Important!!!
        #if fsig & lsig in ARGS Fix
        #
        #

        if Args.METHOD:
            if Args.method.upper() not in ["GET", "POST"]:
                self.Error("This method is not Supported yet")
            method = Args.method.upper()
        else:
            method = "GET"  # Autodetect Method

        if Args.DATA:
            method = "POST"  # Autodetect Method
            data = Args.DATA

        if Args.TARGET:
            target = Args.TARGET

        headers = HTTPHeaders()
        if Args.COOKIE:
            headers.add("Cookie", Args.COOKIE)
        if Args.HEADERS:
            for header in Args.HEADERS:
                values = header.split(':')
                headers.add(*values)


        if Args.CONTAINS is None and Args.RESP_CODE_DET is None:
            self.Error("You need to specify a detection method")

        if Args.CONTAINS:
            detection_args = []
            detection_args.append(Args.CONTAINS[0])  # detection string
            if "cs" in Args.CONTAINS[1:]:  # if case_sensitive
                detection_args.append("cs")
            if Args.REVERSE:
                detection_args.append("rev")
            self.detection_struct.append(["contains", self.contains, detection_args])

        if Args.RESP_CODE_DET:
            detection_args = []
            detection_args.append(Args.RESP_CODE_DET[0])
            if Args.REVERSE:
                detection_args.append("rev")
            self.detection_struct.append(["Response Code Detection", self.resp_code_detection, detection_args])
        #####################################

        if Args.LENGTH:
            ch = Args.LENGTH[0][0]
            length = self.find_length(target, method, self.detection_struct, ch, headers, None)
            print "Allowed Length = " + str(length)

        else:  # Fuzzing using content placeholders loaded from file
            if Args.PAYLOADS:
                payloads = []
                for payload in Args.PAYLOADS:
                    payloads += self.load_payload_file(payload)
            else:
                self.Error("Payloads not Specified")


            if method == "GET":

                if self.fsig not in [str(headers), target]:
                    self.Error("Fuzzing Placeholder not found")

                requests = self.create_GET_requests(target, payloads, headers)
            else:  # Post Packets

                if self.fsig not in [str(headers), target,str(data)]:
                    self.Error("Fuzzing Placeholder not found")
                requests = self.create_POST_requests(
                    target,
                    payloads,
                    data,
                    headers)

            self.fuzz(requests, self.detection_struct)


if __name__ == "__main__":
    #Banner()
    fuzzer = Fuzzer()
    arguments = fuzzer.GetArgs()
    fuzzer.Start(arguments)

