from lxml import etree
import obfuscation_lib


def reverse(string):
    return string[::-1]

def replace(string, old, new):
    return string.replace(old, new)

def payload():
    return "payload"

class XML_Analyzer(object):
    """This is a class which analyzes the XML input tags and performs
     multiple transformations defined by the XML tags.
    It is a helper class for template parser.
    The methods that it contains are the parsing events,"""


    def __init__(self, linking_table):
        self.stack = []
        self.encoded_string = ""
        self.linking_table = linking_table
        print "Parser Info: Parsing Started"

    def start(self, tag, attrib):
        #print("start %s %r" % (tag, dict(attrib)))

        try:
            function = self.linking_table[tag]
        except KeyError:
            print "Parser Warning: Unknown starting tag found (" + tag + "). Ignoring..."
            return

        self.stack.append(["F", function])
        #print "attributes" + str(dict(attrib))
        if len(dict(attrib)) != 0:
            self.stack.append(["A", attrib])

    def end(self, tag):
        #print("end %s" % tag)

        data = ""
        arglist = []

        if tag not in[key for key in self.linking_table]:
            print "Parser Warning: Unknown ending tag found (" + tag + "). Ignoring..."
            return

        while True:
            element = self.stack.pop()
            #print "element = " + str(element)
            if element[0] == 'D':
                data += element[1]
                continue
            break

        if element[0] == 'A':
            args = element[1]
            for key, value in args.iteritems():
                    arglist.append(value)
            function = self.stack.pop()[1]
        else:
            function = element[1]


        if data:
            arglist.append(data)
            arglist.reverse()

        #print "ArgList (" + str(arglist) + ")"
        data = function(*arglist)

        self.stack.append(["D", data])

    def data(self, data):
        #print("data %r" % data)
        self.stack.append(['D', data])

    def comment(self, text):
        print("Parser Info: Comment Found: (%s). Ignoring ..." % text)

    def close(self):
        print("Parser Info: Parsing Complete")
        return self.stack.pop()[1]


class template_parser():
    """This class is provides function for managing the fuzzing templates."""

    def __init__(self):
        self.payload_data = None
        self.linking_table = obfuscation_lib.get_transformations()
        self.linking_table.update({"payload": self.payload})
        self.linking_table.update({"transform_payload": self.transform_payload})

    #This function is needed to be called at the end of the parsing
    #  in order to return the output
    def transform_payload(self, string):
        return string

    def set_payload(self, string):
        self.payload_data = string

    def add_functions(self, functions):
        self.linking_table(functions)

    def transform(self, xml_string, signature="@@@"):
        xml_string = xml_string.replace(signature,"<transform_payload>",1)
        xml_string = xml_string.replace(signature,"</transform_payload>",1)
        #print xml_string
        self.parser = etree.XMLParser(target=XML_Analyzer(self.linking_table))
        return etree.XML(xml_string, self.parser)

    def payload(self):
        if self.payload_data:
            return self.payload_data
        return ""

