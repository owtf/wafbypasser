WAF-Byppaser Module


Run example:

Testing using ResponceCodeDetection 
python fuzzer.py -t 'http://127.0.0.1/xss.php' -pl xss.txt -rcd '400-599,100'  -H "var:@fuzzme@" -p "var=1234" --cookie "Name=tester"

Reverse the ResponceCodeDetection  function (Negative testing).
python fuzzer.py -t 'http://127.0.0.1/xss.php' -pl xss.txt -rcd '400-599'  -H "var:@fuzzme@" -p "var=1234" --cookie "Name=tester" -r


Testing usings CoNTains text
python fuzzer.py -t 'http://127.0.0.1/xss.php' -pl xss.txt -cnt "error"  -H "var:@fuzzme@" -p "var=1234" --cookie "Name=tester"

Testing using does not CoNTains
python fuzzer.py -t 'http://127.0.0.1/xss.php' -pl xss.txt -cnt "error"  -H "var:@fuzzme@" -p "var=1234" --cookie "Name=tester" -r

Testing usings CoNTains case_senvitice text
python fuzzer.py -t 'http://127.0.0.1/xss.php' -pl xss.txt -cnt "ErroR" cs -H "var:@fuzzme@" -p "var=1234" --cookie "Name=tester"