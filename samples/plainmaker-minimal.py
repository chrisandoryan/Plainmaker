from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IBurpExtenderCallbacks

import datetime
import hmac
import json
import base64
import hashlib
from urlparse import urlparse
from urllib import unquote
from base64 import b64encode, b64decode

NAME = "Plainmaker - Minimal"

class IEncryptorDecryptor():
    def encrypt_decrypt_on_http_request(self, uri, method="POST"):
        """
        Perform a custom decryption algorithm and inject the encrypted/decrypted values into HTTP request's headers and body as the result.

         Parameters
        ----------
        uri : str
            Endpoint of the request (e.g., /erangel/v1-onboard-brimo)
        method : str
            Method of the request (e.g., GET or POST)

        Returns
        -------
        dict
            A dictionary that contains the Headers ('headers') and Body ('body') attribute of the decrypted HTTP request.
        """

        return {
            "headers": {
                "Host": "brimo.bri.co.id",
                "X-Device-Id": "INJECTED_BY_PLAINMAKER",
                "X-Random-Key": "INJECTED_BY_PLAINMAKER",
                "User-Agent": "INJECTED_BY_PLAINMAKER",
                "X-Extra-Header": "INJECTED_BY_PLAINMAKER"
            },
            "body": "request=INJECTED_BY_PLAINMAKER"
        }

    def encryption_decryption_on_http_response(self):
        """
        Perform a custom encryption/decryption algorithm and inject the encrypted/decrypted values into HTTP response's statline, headers and body as the result.

        Returns
        -------
        dict
            A dictionary that contains Status Line ('statline'), Headers ('headers') and Body ('body') attributes of the HTTP response.
        """

        return {
            "statline": "HTTP/1.1 200 OK",
            "headers": {
                "date": "INJECTED_BY_PLAINMAKER",
                "cache-control": "INJECTED_BY_PLAINMAKER",
                "pragma": "INJECTED_BY_PLAINMAKER",
                "x-frame-options": "INJECTED_BY_PLAINMAKER"
            },
            "body": "INJECTED_BY_PLAINMAKER"
        }

    def plainify_http_request(self, plain_request, iRequestInfo):
        """
        Return an tampered/injected/modified HTTP request in raw HTTP format
        """

        req_method = self.get_request_method(iRequestInfo)
        req_uri = self.get_request_uri(iRequestInfo)
        
        req_data = self.encrypt_decrypt_on_http_request(req_uri, req_method)
        request = self.construct_tampered_request(plain_request, iRequestInfo, req_data)
        
        return request

    def plainify_http_response(self):
        """
        Return an injected/modified HTTP response in raw HTTP format
        """

        pass

    def construct_tampered_request(self, plain_request, iRequestInfo, req_data):
        orig_headers_array = iRequestInfo.getHeaders()

        tampered_body = req_data['body']
        tampered_headers = orig_headers_array
        for key, value in req_data['headers'].items():
            h_change_index = FloydsHelpers.index_containing_substring(tampered_headers, key)
            header = "%s: %s" % (key, value, )

            if (h_change_index):
                tampered_headers[h_change_index] = header
            else:
                tampered_headers.append(header)
        
        tampered_req = self.build_raw_http_request(tampered_headers, tampered_body)
        print("Tampered Request", tampered_req)

        return tampered_req
    
    def construct_tampered_response(self, plain_request, iRequestInfo, req_data):
        pass

    def build_raw_http_request(self, headers, body):
        req = '\r\n'.join(headers)
        req += 2 * '\r\n' + body
        return req

    def build_raw_http_response(self, headers, body):
        pass
    
    @staticmethod
    def get_request_method(iRequestInfo):
        req_method = iRequestInfo.getMethod()
        return req_method
    
    @staticmethod
    def get_request_uri(iRequestInfo):
        req_uri = urlparse(str(iRequestInfo.getUrl())).path
        return req_uri
    
    @staticmethod
    def get_request_body(plain, iRequestInfo):
        req_body = plain[iRequestInfo.getBodyOffset():]
        return req_body

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):

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
    # implement IHttpListener
    #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == IBurpExtenderCallbacks.TOOL_PROXY and messageIsRequest:
            # Already processed in processProxyMessage
            return
        self.filter_message(toolFlag, messageIsRequest, messageInfo)

    #
    # implement IProxyListener
    #

    def processProxyMessage(self, messageIsRequest, message):
        # Responses are handled as early as possible in processHttpMessage
        if messageIsRequest:
            self.filter_message(IBurpExtenderCallbacks.TOOL_PROXY, messageIsRequest, message.getMessageInfo())

    def filter_message(self, toolFlag, messageIsRequest, messageInfo):
        iRequestInfo = self._helpers.analyzeRequest(messageInfo)
        if not iRequestInfo.getUrl():
            print("iRequestInfo.getUrl() returned None, so bailing out of analyzing this request")
            return
        if not self._callbacks.isInScope(iRequestInfo.getUrl()):
            print(iRequestInfo.getUrl(), " is not in scope")
            return
            
        if messageIsRequest:
            plain_request = FloydsHelpers.jb2ps(messageInfo.getRequest())
            iRequestInfo = self._helpers.analyzeRequest(messageInfo)

            encdec = IEncryptorDecryptor()

            new_req = encdec.plainify_http_request(plain_request, iRequestInfo)
            new_req_bytes = FloydsHelpers.ps2jb(new_req)

            messageInfo.setRequest(new_req_bytes)

        else:
            plain_response = FloydsHelpers.jb2ps(messageInfo.getResponse())
            iResponseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
            # TODO: Handle response modification
            
        pass

class FloydsHelpers(object):
    @staticmethod
    def index_containing_substring(the_list, substring):
        substring = substring.lower()
        for i, s in enumerate(the_list):
            if substring in s.lower():
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
        h = list(headers.split(newline))
        for index, x in enumerate(h):
            if "content-length:" == x[:len("content-length:")].lower():
                h[index] = x[:len("content-length:")] + " " + str(length)
                return newline.join(h)
        else:
            print("WARNING: Couldn't find Content-Length header in request, simply adding this header")
            h.insert(1, "Content-Length: " + str(length))
            return newline.join(h)