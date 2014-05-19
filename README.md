WAF-Byppaser Module


Run example:

python fuzzer.py -t 'http://127.0.0.1/xss.php' -pl xss.txt -d response_code 390-441,100 -H "HEAD:@fuzzme@" -p "var=1234" --cookie "name=user"

python fuzzer.py -t 'http://127.0.0.1/xss.php?xss=@fuzzme@' -pl xss.txt xss2.txt -d contains "string_to_detect" --cookie "name=user"
