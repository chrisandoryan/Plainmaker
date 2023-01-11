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

NAME = "Plainmaker"

class IEncryptorDecryptor():
    def generate_http_request_variables(self, uri, method="POST"):
        """
        Perform a custom encryption/decryption algorithm and inject the encrypted/decrypted values into HTTP request's headers and body as the result.

         Parameters
        ----------
        uri : str
            Endpoint of the request (e.g., /erangel/v1-onboard-brimo)
        method : str
            Method of the request (e.g., GET or POST)

        Returns
        -------
        dict
            A dictionary that contains the Headers ('headers') and Body ('body') attribute of the HTTP request.
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

    def generate_http_response_variables(self):
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

    def get_http_injected_request(self, orig_request, iRequestInfo):
        """Return a decrypted HTTP request in raw HTTP format"""
        
        req_method = iRequestInfo.getMethod()
        req_url = urlparse(str(iRequestInfo.getUrl())).path
        req_variables = self.generate_http_request_variables(req_url, req_method)

        orig_body = orig_request[iRequestInfo.getBodyOffset():]
        orig_headers_array = iRequestInfo.getHeaders()
        orig_headers_string = orig_request[:iRequestInfo.getBodyOffset()]

        tampered_body = req_variables['body']
        tampered_headers = orig_headers_array
        for key, value in req_variables['headers'].items():
            h_change_index = FloydsHelpers.index_containing_substring(tampered_headers, key)
            header = "%s: %s" % (key, value, )

            if (h_change_index):
                tampered_headers[h_change_index] = header
            else:
                tampered_headers.append(header)
        
        tampered_req = self.construct_http_raw_request(tampered_headers, tampered_body)
        return FloydsHelpers.ps2jb(tampered_req)
    
    def get_http_injected_response(self, messageInfo, res_variables):
        """Return a decrypted raw HTTP response in raw HTTP format"""
        pass

    def construct_http_raw_request(self, headers, body):
        req = '\r\n'.join(headers)
        req += 2 * '\r\n' + body
        return req

    def construct_http_raw_response(self, headers, body):
        pass

class SenyumEncryptorDecryptor(IEncryptorDecryptor):
    def generate_http_request_variables(self, uri, auth_access_token, code_challenge, x_auth_token, timestamp=None, body="", method="POST"):        
        v = uri
        x = method.upper()

        T = auth_access_token
        k = datetime.utcnow().isoformat()[:-3]+'Z' if not timestamp else timestamp
        json_body = json.dumps(body, indent=None, separators=(',', ':')) if body else ''

        message = 'path=' + v + '&verb=' + x + '&token=Bearer ' + T + '&timestamp=' + k + '&body=' + json_body
        
        h = hmac.new(code_challenge.encode(), message.encode(), hashlib.sha256)
        signature = base64.b64encode(h.digest())
        
        return {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Linux; Android 8.1.0; Hisense U964) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Mobile Safari/537.36",
                "x-authorization": "Bearer %s" % x_auth_token,
                "authorization": "Bearer %s" % T,
                "bri-timestamp": k,
                "bri-signature": signature,
                "host": "sandbox.outer.api.bri.co.id",
                "Content-Type": "application/json",
            },
            "body": json_body
        }

    def get_http_injected_request(self, orig_request, iRequestInfo):
        return super().get_http_injected_request(orig_request, iRequestInfo)
    
    def get_http_injected_response(self, orig_response):
        return super().get_http_injected_response(orig_response)

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
            req = FloydsHelpers.jb2ps(messageInfo.getRequest())
            iRequestInfo = self._helpers.analyzeRequest(messageInfo)

            encdec = SenyumEncryptorDecryptor()
            new_req = encdec.get_http_injected_request(req, iRequestInfo)
            messageInfo.setRequest(new_req)
        else:
            resp = FloydsHelpers.jb2ps(messageInfo.getResponse())
            if search in resp.lower():
                self.response_body_decode(messageInfo)
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