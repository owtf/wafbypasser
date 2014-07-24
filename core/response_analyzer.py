#This module analyze and format the results


def analyze_responses(responses, http_helper, detection_struct):
    det_resp = []
    undet_resp = []
    det_payloads = []
    undet_payloads = []
    for response in responses:
        detected = False
        for detection in detection_struct:
            if detection["method"](response, detection["arguments"]):
                det_resp.append(response)
                detected = True
                break
        if not detected:
            undet_resp.append(response)
            print str(response)
    print "Detected Requests"
    for resp in det_resp:
        print
        payload = http_helper.get_payload(resp)
        print_response(resp, payload)
        det_payloads.append(payload)
    print
    print "Undetected Requests"
    for resp in undet_resp:
        print
        payload = http_helper.get_payload(resp)
        print_response(resp, payload)
        undet_payloads.append(payload)
    print "List of Detected Payloads"
    for payload in sorted(det_payloads):
        print payload
    print
    print "List of UnDetected Payloads"
    for payload in sorted(undet_payloads):
        print payload
    print
    print "Number 0f HTTP requests: " + str(len(responses))
    print "Number 0f Detected HTTP requests: " + str(len(det_resp))
    print "Number 0f UnDetected HTTP requests: " + str(len(undet_resp))
    print


def print_response(response, payload):
    #print "Detected with: " + detection_method
    print "URL: " + response.request.url
    print "Method: " + response.request.method
    if response.request.body is not None:
        print "Post Data: " + response.request.body
    print "Request Headers: " + format_headers(response.request.headers)
    print "Payload: " + payload


def format_headers(headers):
    formatted_headers = ""
    for header_name, header_value in headers.iteritems():
        formatted_headers += header_name + ": " + header_value + ", "
    return formatted_headers