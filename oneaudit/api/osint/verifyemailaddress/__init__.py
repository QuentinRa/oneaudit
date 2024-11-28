import re
import urllib3
import os.path
from oneaudit.api.osint import OSINTProvider

class VerifyEmailAddressAPI(OSINTProvider):
    def __init__(self, api_keys, cache_only):
       super().__init__(
           api_name='verifyemailaddress',
           request_args={},
           api_keys=api_keys
        )

    def verify_one_email(self, mail_string):
        yield True, {}

    def old_verify(self, mail_string):

        # Return types:
        # exists <- email valid
        # dont_exists <- email is not valid 
        # error_format <- regex does not match
        # error_http <- HTTP error
        # rate_limit <- rate limite exceeded


        http = urllib3.PoolManager()

        pattern = re.compile("")
        if not pattern.match(mail_string):
            return "error_format"
        

        #Let's make the request to the API to check the mail
        request_body = {
            "email":mail_string,
            "index":"0",
            "token":"12345",
            "frommail":"835468954@qq.com",
            "timeout":"10",
            "scan_port":"25"
        }

        encoded_params = urllib3.request.urlencode(request_body)

        response = http.request(
            "POST",
            'https://check.emailverifier.online/bulk-verify-email/functions/quick_mail_verify_no_session.php',
            body=encoded_params,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        response = (response.data.decode('utf-8')) 
        #print(response)
        if '"status":"valid"' in response:
            return "exists"
        elif '"status":"invalid"' in response:
            return "dont_exists"
        else:
            return "error_http"


    # def verify_one_email(self, mail_string):

    #     # Return types:
    #     # exists <- email valid
    #     # dont_exists <- email is not valid 
    #     # error_format <- regex does not match
    #     # error_http <- HTTP error
    #     # rate_limit <- rate limite exceeded

    #     pattern = re.compile("")
    #     if not pattern.match(mail_string):
    #         return "error_format"
        
    #     #http = urllib3.PoolManager()
    #     http = urllib3.ProxyManager("http://103.101.125.18:28062/")

    #     response = http.request('GET', 'https://email-checker.net/')
        
    #     cookies = response.headers.get('Set-Cookie', '')
    #     cookie_header = '; '.join([c.split(';')[0] for c in cookies.split(',')])


    #     body = (response.data.decode('utf-8'))
    #     #return 
    #     token_csrf = re.search('name="_csrf" value="([^"]+)"', body) # <input name=rc type=hidden value=5a4b98e3a11fce98711f312e8af6e51e18c5684fd895b27b882e66a399a6780e>
    #     if token_csrf == None:
    #         return "error_http"
    #     token_csrf = token_csrf.group(1)
    #     #print(token_csrf)
    #     #Let's make the request to the API to check the mail
    #     request_body = {
    #         "email":mail_string,
    #         "_csrf":token_csrf,
    #         "v":"v37",
    #         "g-recaptcha-response-data[check]":"test",
    #         "g-recaptcha-response":""
    #     }

    #     encoded_params = urllib3.request.urlencode(request_body)

    #     response = http.request(
    #         "POST",
    #         'https://email-checker.net/check',
    #         body=encoded_params,
    #         headers={"Content-Type": "application/x-www-form-urlencoded",
    #             'Cookie': cookie_header
    #         }
    #     )

    #     response = (response.data.decode('utf-8')) 
    #     #print(response)
    #     if '<span class="green">OK</span>' in response:
    #         return "exists"
    #     elif '<span class="red">BAD</span>' in response:
    #         return "dont_exists"
    #     elif 'Limit Exceeded' in response:
    #         return "rate_limit"
    #     else:
    #         return "error_http"
