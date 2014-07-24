import argparse


def get_args():
        parser = argparse.ArgumentParser(description='OWTF WAF-BYPASER MODULE')

        parser.add_argument("-X", "--request",
                            dest="METHOD",
                            action='store',
                            nargs="+",
                            help="Specify Method . (Ex: -X GET . \
                            The option @method@ loads all the HTTPmethods that\
                             are in ./payload/HTTPmethods/methods.txt).\
                              Custom methods can be defined in this file.")

        parser.add_argument("-C", "--cookie",
                            dest="COOKIE",
                            action='store',
                            help="Insert a cookie value. \
                            (Ex --cookie 'var=value')")

        parser.add_argument("-t", "--target",
                            dest="TARGET",
                            action='store',
                            required=True,
                            help="The target url")

        parser.add_argument("-H", "--headers",
                            dest="HEADERS",
                            action='store',
                            nargs='*',
                            help="Additional headers \
                            (ex -header 'Name:value' 'Name2:value2')")
        parser.add_argument("-L", "--length",
                            dest="LENGTH",
                            action='store',
                            nargs=1,
                            help="Finds the Length of a content placeholder. \
                                 Parameter is a valid fuzzing character\
                                 (Ex -L 'A')")

        parser.add_argument("-p", "--data",
                            dest="DATA",
                            action='store',
                            help="POST data (ex --data 'var=value')")

        parser.add_argument("-cnt", "--contains",
                            dest="CONTAINS",
                            action='store',
                            nargs='+',
                            help="DETECTION METHOD(ex1 -cnt 'signature'  \n) \
                                 Optional Arguments:\n \
                                  Case sensitive :\n \
                                 (ex2)-cnt 'signature' cs")
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
                            help="Reverse the detection method.\
                            (Negative detection)")

        parser.add_argument("-pl", "--payloads",
                            dest="PAYLOADS",
                            action='store',
                            nargs='*',
                            help="FILE with payloads')(Ex file1 , file2)")

        parser.add_argument("-hpps", "--hpp_source",
                            dest="HPP_SOURCE",
                            action='store',
                            choices=['url', 'data', 'cookie'],
                            help="Options: URL, DATA or COOKIE")

        parser.add_argument("-hppp", "--hpp_param_name",
                            dest="HPP_PARAM_NAME",
                            action='store',
                            help="HPP parameter name")

        parser.add_argument("-hppa", "--hpp_attack_method",
                            dest="HPP_ATTACKING_METHOD",
                            action='store',
                            choices=['asp'],
                            help="ASP attacking method splits the payload at \
                            the ',' character and send an http request with \
                             multiple instances of the same parameter.")

        parser.add_argument("-fs", "--fuzzing_signature",
                            dest="FUZZING_SIG",
                            action='store',
                            help="The default fuzzing signature is @@@.\
                             You can change it with a custom signature.")

        parser.add_argument("-das", "--detect_allowed_sources",
                            dest="DETECT_ALLOWED_SOURCES",
                            action='store_true',
                            help="This functionality detects the the allowed \
                             sources for a parameter. (Ex if the web app is \
                             handling a parameter in way like \
                             $REQUEST[param]).")

        parser.add_argument("-am", "--accepted_method",
                            dest="ACCEPTED_METHOD",
                            action='store',
                            help="The accepted Method")

        parser.add_argument("-apv", "--accepted_param_value",
                            dest="ACCEPTED_PARAM_VALUE",
                            action='store',
                            help="Accepted parameter value")

        parser.add_argument("-pn", "--param_name",
                            dest="PARAM_NAME",
                            action='store',
                            help="Testing parameter name")

        parser.add_argument("-ps", "--param_source",
                            dest="PARAM_SOURCE",
                            action='store',
                            choices=['URL', 'DATA', 'COOKIE', 'HEADER'],
                            help="Specifies the parameters position.")
        parser.add_argument("-d", "--delay",
                            dest="DELAY",
                            action='store',
                            type=int,
                            help="Changes the Fuzzing method from \
                                 asynchronous to synchronous(slower). This \
                                 Allows you to follow cookies and specify a \
                                 delay time in seconds before sending a \
                                 request.")
        parser.add_argument("-fc", "--follow-cookies",
                            dest="FOLLOW_COOKIES",
                            action='store_true',
                            help="Changes the Fuzzing method from \
                                 asynchronous to synchronous(slower). This \
                                 Allows you to follow cookies and specify a \
                                 delay time in seconds before sending a \
                                 request.")
        parser.add_argument("-ct", "--content-type",
                            dest="CONTENT_TYPE",
                            action='store_true',
                            help="This will fuzz the Content-Type with a/"
                                 " list of content types.")

        return parser.parse_args()