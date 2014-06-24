WAF Byppaser module assists the penetration testers to diagnose WAF rules and bypass WAFs.


Run example:

Testing using ResponceCodeDetection.
This example is fuzzing url using a payload list loaded from file, some post data, a header and a cookie.
python wafbypasser.py -t 'http://127.0.0.1/xss.php?xss=@@@fuzzhere@@@' -pl payloadlist.txt -rcd '200-599,100'  -H "var:1234" -p "var=1234" --cookie "name=tester"
Same example as above but fuzzing headers

python wafbypasser.py -t 'http://127.0.0.1/xss.php?xss=1' -pl xss.txt -rcd '200-599,100'  -H "header2:10" "var:@@@fuzzhere@@@" -p "var=1234" --cookie "name=tester"

Reverse the ResponceCodeDetection  function (Negative testing).
python wafbypasser.py -t 'http://127.0.0.1/xss.php?xss=1' -pl xss.txt -rcd '200-599,100'  -H "header2:10" "var:@@@fuzzhere@@@" -p "var=1234" --cookie "name=tester" -r

Testing usings CoNTains detection function text
python wafbypasser.py -t 'http://127.0.0.1/xss.php?xss=@@@fuzzhere@@@' -pl payloadlist.txt --contains 'error' -H "var:1234" -p "var=1234" --cookie "name=tester"

Testing usings CoNTains case_senvitice text
python wafbypasser.py -t 'http://127.0.0.1/xss.php?xss=@@@fuzzhere@@@' -pl payloadlist.txt --contains 'ErrOr' cs -H "var:1234" -p "var=1234" --cookie "name=tester"

Finding for the fuzzing placeholder allowed length
python fuzzer.py -t http://demo.testfire.net?var=@@@length@@@ -cnt "long" -L A
Example run. The A is a white-listed character.
[root@localhost WAF_Bypasser]# python wafbypasser.py -t http://demo.testfire.net?var=@@@length@@@ -cnt "long" -L A
Allowed Length = 16180

HTTP Parameter Pollution
ASP mode
This mode is spliting the payload at the comma ',' character and it is sending it to a different variable

python wafbypasser.py -t http://127.0.0.1/xss.php -pl hpp.txt --contains 'whatever' --hpp_param_name xss --hpp_source url --hpp_attack_method asp -X GET

Detecting Allowed sources
python wafbypasser.py -t http://127.0.0.1/xss.php --contains 'whatever' --detect_allowed_sources --accepted_method GET --param_name xss --accepted_param_value test --param_source URL

Fuzzing using templates and transforming payloads
The tranformation functions are defined in the obfuscation_lib.py.
python wafbypasser.py -t 'http://127.0.0.1/xss.php?' -pl xss2.txt -rcd '200-599,100' --data "xss=@@@<reverse><payload/></reverse>@@@"
