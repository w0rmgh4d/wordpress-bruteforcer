# wordpress-bruteforcer
WordPress credential testing tool for authorized security assessments and lab environments

How to use:

with proxy:
python3 wp_bruteforcer.py --i-have-authorization -t targets.txt -u usernames.txt -p passwords.txt -P proxies.txt -c 100 --per-host 5 --check-wp --stop-on-success -o results.csv

no proxy
python3 wp_bruteforcer.py --i-have-authorization -t targets.txt -u usernames.txt -p passwords.txt --no-proxy -c 100 --per-host 5 --check-wp --stop-on-success -o results.csv
