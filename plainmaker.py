from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IBurpExtenderCallbacks
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

import datetime
import hmac
import json
import base64
import hashlib
from urlparse import urlparse
from urllib import unquote
from base64 import b64encode, b64decode

# Jython imports
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec
from javax.crypto.spec import GCMParameterSpec
from javax.crypto.spec import SecretKeySpec

NAME = "Plainmaker"

class IEncryptorDecryptor():
    MODE_REQUEST_ENCRYPT = 0
    MODE_REQUEST_DECRYPT = 1
    MODE_RESPONSE_ENCRYPT = 2
    MODE_RESPONSE_DECRYPT = 3

    def encrypt_http_request(self, uri, method="POST"):
        """
        Perform a custom encryption algorithm and inject the encrypted values into HTTP request's headers and body as the result.

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
                "X-Device-Id": "INJECTED_BY_PLAINMAKER_REQUEST_ENCRYPTION",
                "X-Random-Key": "INJECTED_BY_PLAINMAKER_REQUEST_ENCRYPTION",
                "User-Agent": "INJECTED_BY_PLAINMAKER_REQUEST_ENCRYPTION",
                "X-Extra-Header": "INJECTED_BY_PLAINMAKER_REQUEST_ENCRYPTION"
            },
            "body": "request=INJECTED_BY_PLAINMAKER_REQUEST_ENCRYPTION"
        }

    def decrypt_http_request(self, uri, method="POST"):
        """
        Perform a custom decryption algorithm and inject the decrypted values into HTTP request's headers and body as the result.

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
                "X-Device-Id": "INJECTED_BY_PLAINMAKER_REQUEST_DECRYPTION",
                "X-Random-Key": "INJECTED_BY_PLAINMAKER_REQUEST_DECRYPTION",
                "User-Agent": "INJECTED_BY_PLAINMAKER_REQUEST_DECRYPTION",
                "X-Extra-Header": "INJECTED_BY_PLAINMAKER_REQUEST_DECRYPTION"
            },
            "body": "request=INJECTED_BY_PLAINMAKER_REQUEST_DECRYPTION"
        }

    def encrypt_http_response(self):
        """
        Perform a custom encryption algorithm and inject the encrypted values into HTTP response's statline, headers and body as the result.

        Returns
        -------
        dict
            A dictionary that contains Status Line ('statline'), Headers ('headers') and Body ('body') attributes of the HTTP response.
        """

        return {
            "statline": "HTTP/1.1 200 OK",
            "headers": {
                "date": "INJECTED_BY_PLAINMAKER_RESPONSE_ENCRYPTION",
                "cache-control": "INJECTED_BY_PLAINMAKER_RESPONSE_ENCRYPTION",
                "pragma": "INJECTED_BY_PLAINMAKER_RESPONSE_ENCRYPTION",
                "x-frame-options": "INJECTED_BY_PLAINMAKER_RESPONSE_ENCRYPTION"
            },
            "body": "INJECTED_BY_PLAINMAKER_RESPONSE_ENCRYPTION"
        }

    def decrypt_http_response(self):
        """
        Perform a custom decryption algorithm and inject the decrypted values into HTTP response's statline, headers and body as the result.

        Returns
        -------
        dict
            A dictionary that contains Status Line ('statline'), Headers ('headers') and Body ('body') attributes of the HTTP response.
        """

        return {
            "statline": "HTTP/1.1 200 OK",
            "headers": {
                "date": "INJECTED_BY_PLAINMAKER_RESPONSE_DECRYPTION",
                "cache-control": "INJECTED_BY_PLAINMAKER_RESPONSE_DECRYPTION",
                "pragma": "INJECTED_BY_PLAINMAKER_RESPONSE_DECRYPTION",
                "x-frame-options": "INJECTED_BY_PLAINMAKER_RESPONSE_DECRYPTION"
            },
            "body": "INJECTED_BY_PLAINMAKER_RESPONSE_DECRYPTION"
        }

    def handle_http_request(self, plain_request, iRequestInfo, operation_mode):
        """
        Return an tampered/injected/modified HTTP request in raw HTTP format
        """

        req_method = self.get_request_method(iRequestInfo)
        req_uri = self.get_request_uri(iRequestInfo)
        
        request_data = {}
        if (operation_mode == IEncryptorDecryptor.MODE_REQUEST_ENCRYPT):
            request_data = self.encrypt_http_request(req_uri, req_method)
        elif (operation_mode == IEncryptorDecryptor.MODE_REQUEST_DECRYPT):
            request_data = self.decrypt_http_request(req_uri, req_method)
        else:
            print("Unknown operation_mode (%s). Request will not be modified." % operation_mode)

        burp_request = self.modify_burp_request(plain_request, iRequestInfo, request_data)
        return burp_request

    def handle_http_response(self):
        """
        Return an injected/modified HTTP response in raw HTTP format
        """

        pass

    def modify_burp_request(self, plain_request, iRequestInfo, request_data):
        orig_headers_array = iRequestInfo.getHeaders()

        tampered_body = request_data['body']
        tampered_headers = orig_headers_array
        for key, value in request_data['headers'].items():
            h_change_index = FloydsHelpers.index_containing_substring(tampered_headers, key)
            header = "%s: %s" % (key, value, )

            if (h_change_index):
                tampered_headers[h_change_index] = header
            else:
                tampered_headers.append(header)
        
        tampered_req = self.build_raw_http_request(tampered_headers, tampered_body)
        print("Tampered Request", tampered_req)

        return tampered_req
    
    def modify_burp_response(self, plain_request, iRequestInfo, response_data):
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

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IMessageEditorTabFactory):
    HTTP_HANDLER = 0
    PROXY_HANDLER = 1

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

        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        print("Loaded " + NAME + " successfully!")

    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        self.plainmaker_tab = PlainmakerTab(self, controller, editable)
        return self.plainmaker_tab

    #
    # implement IHttpListener
    #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == IBurpExtenderCallbacks.TOOL_PROXY:
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
        
        encdec = IEncryptorDecryptor()

        if messageIsRequest:
            plain_request = FloydsHelpers.jb2ps(messageInfo.getRequest())
            iRequestInfo = self._helpers.analyzeRequest(messageInfo)

            # 1. Request Decryption Stage
            # If the message is a HTTP request and the handler is processProxyMessage(),
            # Then Plainmaker will decrypt the HTTP request so the user can view/edit them in their plaintext form before forwarding it to the destination server.
            if handler == self.PROXY_HANDLER:
                print("Request Decryption Stage")

                new_req = encdec.handle_http_request(
                    plain_request, 
                    iRequestInfo, 
                    operation_mode=IEncryptorDecryptor.MODE_REQUEST_DECRYPT
                )
                new_req_bytes = FloydsHelpers.ps2jb(new_req)
                messageInfo.setRequest(new_req_bytes)
            
            # 2. Request Re-encryption Stage
            # If the message is HTTP request and the handler is processHttpMessage,
            # Then Plainmaker will encrypt (or re-encrypt) the HTTP request so that the destination server still receives a valid (encrypted) HTTP request payload.
            else:
                print("Request Re-encryption Stage")
                
                new_req = encdec.handle_http_request(
                    plain_request, 
                    iRequestInfo, 
                    operation_mode=IEncryptorDecryptor.MODE_REQUEST_ENCRYPT
                )
                new_req_bytes = FloydsHelpers.ps2jb(new_req)
                messageInfo.setRequest(new_req_bytes)
        else:
            plain_response = FloydsHelpers.jb2ps(messageInfo.getResponse())
            iResponseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())

            # 3. Response Decryption Stage
            # If the message is HTTP response and the handler is processHttpMessage, 
            # Then Plainmaker will decrypt the HTTP response so user can view/edit them in their plaintext form before forwarding it to the client.
            if handler == self.HTTP_HANDLER:
                print("Response Decryption Stage")

                pass
                
            # 4. Response Re-encryption Stage
            # If the message is HTTP response and the handler is processProxyMessage,
            # Then Plainmaker will encrypt the HTTP response so that the client still receives a valid (encrypted) HTTP response payload.
            else:
                print("Response Re-encryption Stage")

                pass

        pass

class PlainmakerTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        
        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "Plainmaker"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        return isRequest and self._extender._helpers.getRequestParameter(content, "data") is not None
        
    def setMessage(self, content, isRequest):
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            print("Tab Content", content)
            self._txtInput.setText(content)
            self._txtInput.setEditable(self._editable)
        
        # remember the displayed content
        self._currentMessage = content
    
    def getMessage(self):
        # determine whether the user modified the deserialized data
        if self._txtInput.isTextModified():
            # reserialize the data
            text = self._txtInput.getText()
            input = self._extender._helpers.urlEncode(self._extender._helpers.base64Encode(text))
            
            # update the request with the new parameter value
            return self._extender._helpers.updateParameter(self._currentMessage, self._extender._helpers.buildParameter("data", input, IParameter.PARAM_BODY))
            
        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()

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