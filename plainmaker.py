from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import ICookie
from burp import IBurpExtenderCallbacks

import re
import datetime
import hmac
import json
import base64
import hashlib
from urlparse import urlparse, parse_qs, parse_qsl, urlunparse
from urllib import unquote, quote_plus, urlencode
from base64 import b64encode, b64decode
from subprocess import Popen, PIPE
from Cookie import SimpleCookie

# Jython imports
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec
from javax.crypto.spec import GCMParameterSpec
from javax.crypto.spec import SecretKeySpec

"""
Plainmaker Extension
https://github.com/chrisandoryan/Plainmaker

Created by Chrisando Ryan
"""

NAME = "Plainmaker"

class IEncryptorDecryptor():
    MODE_REQUEST_ENCRYPT = 0
    MODE_REQUEST_DECRYPT = 1
    MODE_RESPONSE_ENCRYPT = 2
    MODE_RESPONSE_DECRYPT = 3

    def should_filter_cookies(self):
        """
        Implement logic to determine whether cookie filtering mechanism should be executed. This allows you to remove / override cookie value only when certain conditions are met.

        Parameters
        ----------
        None

        Returns
        -------
        boolean
            A boolean indicating whether the cookie removal / overriden mechanism should be invoked.
        """

        return True
    
    def get_unwanted_cookies(self):
        """
        Implement this method to perform automatic removal / value override of certain cookies in the request.

        Parameters
        ----------
        None

        Returns
        -------
        tuple
            A tuple that contains the list of cookies that want to be removed / overriden. Cookie keys can accept RegEx pattern. Set the cookie value to 'None' to remove the cookie from the request entirely.
        """

        return [
            ('PHPSESSID', None),
            ('laravel_*', 'new_value_here'),
        ]

    def encrypt_http_request(self, original_request, iRequestInfo):
        """
        Implement this method and perform a custom encryption algorithm and inject the encrypted values into HTTP request's headers and body as the result.

        Parameters
        ----------
        original_request : str
            The received HTTP request in plain format
        iRequestInfo : interface
            A Burp's interface used to retrieve key details about an HTTP request.

        Returns
        -------
        dict
            A dictionary that contains the Headers ('headers'), Params ('params'), and Body ('body') attribute of the decrypted HTTP request.
        """

        req_method = self.get_request_method(iRequestInfo)
        req_uri = self.get_request_uri(iRequestInfo)

        return {
            "headers": {},
            "params": {},
            "body": False
        }

    def decrypt_http_request(self, original_request, iRequestInfo):
        """
        Implement this method and perform a custom decryption algorithm and inject the decrypted values into HTTP request's headers and body as the result.

        Parameters
        ----------
        original_request : str
            The received HTTP request in plain format
        iRequestInfo : interface
            A Burp's interface used to retrieve key details about an HTTP request.

        Returns
        -------
        dict
            A dictionary that contains the Headers ('headers'), Params ('params'), and Body ('body') attribute of the decrypted HTTP request.
        """

        return {
            "headers": {},
            "params": {},
            "body": False
        }

    def encrypt_http_response(self, original_response, iResponseInfo):
        """
        Implement this method and perform a custom encryption algorithm and inject the encrypted values into HTTP response's statline, headers and body as the result.

        Parameters
        ----------
        original_response : str
            The received HTTP response in plain format
        iResponseInfo : interface
            A Burp's interface used to retrieve key details about an HTTP response.

        Returns
        -------
        dict
            A dictionary that contains Headers ('headers'), Params ('params'), and Body ('body') attributes of the HTTP response.
        """

        return {
            "headers": {},
            "params": {},
            "body": False
        }

    def decrypt_http_response(self, original_response, iResponseInfo):
        """
        Implement this method and perform a custom decryption algorithm and inject the decrypted values into HTTP response's statline, headers and body as the result.

        Parameters
        ----------
        original_response : str
            The received HTTP response in plain format
        iResponseInfo : interface
            A Burp's interface used to retrieve key details about an HTTP response.

        Returns
        -------
        dict
            A dictionary that contains Headers ('headers'), Params ('params'), and Body ('body') attributes of the HTTP response.
        """

        return {
            "headers": {},
            "params": {},
            "body": False
        }

    def handle_http_request(self, original_request, iRequestInfo, operation_mode):
        """
        Return an tampered/injected/modified HTTP request in raw HTTP format
        """
        
        request_data = {}
        if (operation_mode == IEncryptorDecryptor.MODE_REQUEST_ENCRYPT):
            request_data = self.encrypt_http_request(original_request, iRequestInfo)
        elif (operation_mode == IEncryptorDecryptor.MODE_REQUEST_DECRYPT):
            request_data = self.decrypt_http_request(original_request, iRequestInfo)
        else:
            print("WARNING: unknown operation_mode: %s. Request will not be modified." % operation_mode)

        burp_request = self.modify_burp_request(original_request, iRequestInfo, request_data)
        return burp_request

    def handle_http_response(self, original_response, iResponseInfo, operation_mode):
        """
        Return an injected/modified HTTP response in raw HTTP format
        """

        response_data = {}
        if (operation_mode == IEncryptorDecryptor.MODE_RESPONSE_ENCRYPT):
            response_data = self.encrypt_http_response(original_response, iResponseInfo)
        elif (operation_mode == IEncryptorDecryptor.MODE_RESPONSE_DECRYPT):
            response_data = self.decrypt_http_response(original_response, iResponseInfo)
        else:
            print("WARNING: unknown operation_mode: %s. Response will not be modified." % operation_mode)

        burp_request = self.modify_burp_response(original_response, iResponseInfo, response_data)
        return burp_request

    def filter_unwanted_cookies(self, cookies):
        list_unwanted_cookies = self.get_unwanted_cookies()

        if self.should_filter_cookies():
            for pattern, value in list_unwanted_cookies:
                for ck in cookies:
                    if re.search(pattern, ck):
                        print('Cookie value to be set: ', value)
                        if value:
                            cookies[ck] = value
                            print("Updating cookie %s into new value: %s" % (ck, value))
                        else:
                            print("Deleting cookie %s" % (ck))
                            del cookies[ck]
                    
        return cookies

    def modify_burp_request(self, original_request, iRequestInfo, request_data):
        orig_headers_array = iRequestInfo.getHeaders()

        # Update Cookie
        for i, header in enumerate(orig_headers_array):
            if header.lower().startswith("cookie:"):
                cookies = SimpleCookie()
                cookies.load(header.split(":")[1].strip().encode('ascii', 'ignore'))
                cookies = {k: v.value for k, v in cookies.items()}
                
                cookies = self.filter_unwanted_cookies(cookies)
                cookie_string = "; ".join([str(x) + "=" + str(y) for x,y in cookies.items()])
                orig_headers_array[i] = "Cookie: %s" % (cookie_string)
        
        orig_body = IEncryptorDecryptor.get_http_body(original_request, iRequestInfo)

        tampered_body = request_data['body'] or orig_body
        tampered_params = request_data['params'] or None
        tampered_headers = orig_headers_array

        # Update Query Param
        if tampered_params:
            request_line = orig_headers_array[0]
            method, url, http_version = request_line.split(' ', 2)
            updated_path = IEncryptorDecryptor.update_query_params(url, tampered_params)
            orig_headers_array[0] = "%s %s %s" % (method, updated_path, http_version)
            print("New URL: ", orig_headers_array[0])

        # Update Header
        for key, value in request_data['headers'].items():
            h_change_index = FloydsHelpers.index_containing_substring(tampered_headers, key)
            header = "%s: %s" % (key, value, )

            if (h_change_index != -1):
                tampered_headers[h_change_index] = header
            else:
                tampered_headers.append(header)
        
        custom_request = IEncryptorDecryptor.build_raw_http(tampered_headers, tampered_body)
        print("Tampered Request", custom_request)

        return custom_request
    
    def modify_burp_response(self, original_response, iResponseInfo, response_data):
        orig_headers_array = iResponseInfo.getHeaders()
        orig_body = IEncryptorDecryptor.get_http_body(original_response, iResponseInfo)

        tampered_body = response_data['body'] or orig_body
        tampered_headers = orig_headers_array
        for key, value in response_data['headers'].items():
            h_change_index = FloydsHelpers.index_containing_substring(tampered_headers, key)
            header = "%s: %s" % (key, value, )

            if (h_change_index != -1):
                tampered_headers[h_change_index] = header
            else:
                tampered_headers.append(header)
        
        custom_response = IEncryptorDecryptor.build_raw_http(tampered_headers, tampered_body)
        # print("Tampered Response", custom_response)

        return custom_response

    @staticmethod
    def build_raw_http(headers, body):
        newline = "\r\n"
        headers = FloydsHelpers.fix_content_length(headers, len(body), newline)
        req = headers        
        req += 2 * newline + body
        return req
    
    @staticmethod
    def get_request_method(iRequestInfo):
        req_method = iRequestInfo.getMethod()
        return req_method
    
    @staticmethod
    def get_request_uri(iRequestInfo):
        req_uri = urlparse(str(iRequestInfo.getUrl())).path
        return req_uri
    
    @staticmethod
    def get_request_params(iRequestInfo):
        req_params = urlparse(str(iRequestInfo.getUrl())).query
        return req_params
    
    @staticmethod
    def update_query_params(url, params_list):
        url_parts = list(urlparse(url))
        url_parts[4] = urlencode(params_list)

        return urlunparse(url_parts)
    
    @staticmethod
    def get_http_body(plain, iReqResInfo):
        req_body = plain[iReqResInfo.getBodyOffset():]
        return req_body

    @staticmethod
    def run_external_script(path_to_script, *args):
        cmd = ["python3", path_to_script] + list(args)

        proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
        output = proc.stdout.read()
        proc.stdout.close()

        err = proc.stderr.read()
        proc.stderr.close()
        sys.stdout.write(err)

        return output

#####################################################################
# TODO: Write and implement your own encryptor-decryptor class here.
#####################################################################

class MyCustomEncryptorDecryptor(IEncryptorDecryptor, object):
    def __init__(self):
        super(MyCustomEncryptorDecryptor, self).__init__()

    def encrypt_http_request(self, original_request, iRequestInfo):
        return {
            "headers": {},
            "params": {},
            "body": False
        }
    
    def encrypt_http_response(self, original_response, iResponseInfo):
        return {
            "headers": {},
            "params": {},
            "body": False
        }
    
    def decrypt_http_request(self, original_request, iRequestInfo):
        return {
            "headers": {},
            "params": {},
            "body": False
        }
    
    def decrypt_http_response(self, original_response, iResponseInfo):
        return {
            "headers": {},
            "params": {},
            "body": False
        }

#####################################################################
# End of section.
#####################################################################

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
    HTTP_HANDLER = 0
    PROXY_HANDLER = 1

    def __init__(self):
        # TODO: Create a new instance of your encryptor-decryptor class here.
        encdec = MyCustomEncryptorDecryptor()

        self.encdec = encdec

    def registerExtenderCallbacks(self, callbacks):

        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName(NAME)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)

        print("Loaded " + NAME + " successfully!")

    #
    # implement Cookie Filtering
    #

    # def filter_unwanted_cookies(self):
    #     list_unwanted_cookies = self.encdec.get_unwanted_cookies()
    #     cookies = self._callbacks.getCookieJarContents()
    #     for pattern, value in list_unwanted_cookies:
    #         for cookie in cookies:
    #             print("%s = %s" % (cookie.getName(), cookie.getValue()))
    #             if re.search(pattern, cookie.getName()):
    #                 print('Cookie value to be set: ', value)
    #                 if value:
    #                     new_cookie = Cookie(cookie.getDomain(), cookie.getName(), value, cookie.getPath(), cookie.getExpiration())
    #                     print("Updating cookie %s into new value: %s" % (cookie.getName(), value))
    #                 else:
    #                     new_cookie = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(), cookie.getExpiration())
    #                     print("Deleting cookie %s" % (cookie.getName()))
                    
    #                 self._callbacks.updateCookieJar(new_cookie)
        
    #     return

    #
    # implement IHttpListener
    #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == IBurpExtenderCallbacks.TOOL_PROXY or toolFlag ==  IBurpExtenderCallbacks.TOOL_INTRUDER or toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER:
            self.filter_message(self.HTTP_HANDLER, messageIsRequest, messageInfo)

    #
    # implement IProxyListener
    #
    def processProxyMessage(self, messageIsRequest, message):
        self.filter_message(self.PROXY_HANDLER, messageIsRequest, message.getMessageInfo())

    def filter_message(self, handler, messageIsRequest, messageInfo):
        iRequestInfo = self._helpers.analyzeRequest(messageInfo)
        if not iRequestInfo.getUrl():
            print("iRequestInfo.getUrl() returned None, so bailing out of analyzing this request")
            return
        if not self._callbacks.isInScope(iRequestInfo.getUrl()):
            print(iRequestInfo.getUrl(), " is not in scope")
            return
        
        if messageIsRequest:
            original_request = FloydsHelpers.jb2ps(messageInfo.getRequest())
            iRequestInfo = self._helpers.analyzeRequest(messageInfo)
            # print("Original Request", original_request)

            # 1. Request Decryption Stage
            # If the message is a HTTP request and the handler is iProxyListener,
            # Then Plainmaker will decrypt the HTTP request so the user can view/edit them in their plaintext form before forwarding it to the destination server.
            if handler == self.PROXY_HANDLER:
                print("1. Request Decryption Stage")

                new_req = self.encdec.handle_http_request(
                    original_request, 
                    iRequestInfo, 
                    operation_mode=IEncryptorDecryptor.MODE_REQUEST_DECRYPT
                )
                new_req_bytes = FloydsHelpers.ps2jb(new_req)
                messageInfo.setRequest(new_req_bytes)
            
            # 2. Request Re-encryption Stage
            # If the message is HTTP request and the handler is iHttpListener,
            # Then Plainmaker will encrypt (or re-encrypt) the HTTP request so that the destination server still receives a valid (encrypted) HTTP request payload.
            else:
                print("2. Request Re-encryption Stage")
                
                new_req = self.encdec.handle_http_request(
                    original_request, 
                    iRequestInfo, 
                    operation_mode=IEncryptorDecryptor.MODE_REQUEST_ENCRYPT
                )
                new_req_bytes = FloydsHelpers.ps2jb(new_req)
                messageInfo.setRequest(new_req_bytes)
        else:
            original_response = FloydsHelpers.jb2ps(messageInfo.getResponse())
            iResponseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
            # print("Original Response", original_response)

            # 3. Response Decryption Stage
            # If the message is HTTP response and the handler is iHttpListener, 
            # Then Plainmaker will decrypt the HTTP response so user can view/edit them in their plaintext form before forwarding it to the client.
            if handler == self.HTTP_HANDLER:
                print("3. Response Decryption Stage")

                new_res = self.encdec.handle_http_response(
                    original_response, 
                    iResponseInfo, 
                    operation_mode=IEncryptorDecryptor.MODE_RESPONSE_DECRYPT
                )

                # print("New Res", new_res)
                new_res_bytes = FloydsHelpers.ps2jb(new_res)
                messageInfo.setResponse(new_res_bytes)
                
            # 4. Response Re-encryption Stage
            # If the message is HTTP response and the handler is iProxyListener,
            # Then Plainmaker will encrypt the HTTP response so that the client still receives a valid (encrypted) HTTP response payload.
            else:
                print("4. Response Re-encryption Stage")
                new_res = self.encdec.handle_http_response(
                    original_response, 
                    iResponseInfo, 
                    operation_mode=IEncryptorDecryptor.MODE_RESPONSE_ENCRYPT
                )
                new_res_bytes = FloydsHelpers.ps2jb(new_res)
                messageInfo.setResponse(new_res_bytes)

        pass

class FloydsHelpers(object):
    @staticmethod
    def index_containing_substring(the_list, substring):
        substring = substring.lower()
        for i, s in enumerate(the_list):
            if substring == s[:len(substring)].lower():
                return i
        return -1

    @staticmethod
    def jb2ps(arr):
        """
        Turns Java byte arrays into Python str
        :param arr: [65, 65, 65]
        :return: 'AAA'
        """
        return ''.join(map(lambda x: chr(x % 256), arr))

    @staticmethod
    def ps2jb(arr):
        """
        Turns Python str into Java byte arrays
        :param arr: 'AAA'
        :return: [65, 65, 65]
        """
        return [ord(x) if ord(x) < 128 else ord(x) - 256 for x in arr]

    @staticmethod
    def u2s(uni):
        """
        Turns unicode into str/bytes. Burp might pass invalid Unicode (e.g. Intruder Bit Flipper).
        This seems to be the only way to say "give me the raw bytes"
        :param uni: u'https://example.org/invalid_unicode/\xc1'
        :return: 'https://example.org/invalid_unicode/\xc1'
        """
        if isinstance(uni):
            return uni.encode("iso-8859-1", "ignore")
        else:
            return uni
    
    @staticmethod
    def fix_content_length(headers, length, newline):
        if length > 0:
            exists = False
            for index, x in enumerate(headers):
                if "content-length:" == x[:len("content-length:")].lower():
                    headers[index] = x[:len("content-length:")] + " " + str(length)
                    exists = True
            if not exists:
                print("WARNING: Couldn't find Content-Length header in request, simply adding this header")
                headers.insert(1, "Content-Length: " + str(length))
        else:
            print("WARNING: content-length is 0, not injecting header")
        
        return newline.join(headers)

class Cookie(ICookie):

    def getDomain(self):
        return self.cookie_domain

    def getPath(self):
        return self.cookie_path

    def getExpiration(self):
        return self.cookie_expiration

    def getName(self):
        return self.cookie_name

    def getValue(self):
        return self.cookie_value

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None, cookie_expiration=None):
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration