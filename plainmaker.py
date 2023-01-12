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
from urllib import unquote, quote_plus
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

    def encrypt_http_request(self, plain_request, iRequestInfo):
        """
        Perform a custom encryption algorithm and inject the encrypted values into HTTP request's headers and body as the result.

        Parameters
        ----------
        plain_request : str
            The received HTTP request in plain format
        iRequestInfo : interface
            A Burp's interface used to retrieve key details about an HTTP request.

        Returns
        -------
        dict
            A dictionary that contains the Headers ('headers') and Body ('body') attribute of the decrypted HTTP request.
        """

        req_method = self.get_request_method(iRequestInfo)
        req_uri = self.get_request_uri(iRequestInfo)

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

    def decrypt_http_request(self, plain_request, iRequestInfo):
        """
        Perform a custom decryption algorithm and inject the decrypted values into HTTP request's headers and body as the result.

        Parameters
        ----------
        plain_request : str
            The received HTTP request in plain format
        iRequestInfo : interface
            A Burp's interface used to retrieve key details about an HTTP request.

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

    def encrypt_http_response(self, plain_response, iResponseInfo):
        """
        Perform a custom encryption algorithm and inject the encrypted values into HTTP response's statline, headers and body as the result.

        Parameters
        ----------
        plain_response : str
            The received HTTP response in plain format
        iResponseInfo : interface
            A Burp's interface used to retrieve key details about an HTTP response.

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

    def decrypt_http_response(self, plain_response, iResponseInfo):
        """
        Perform a custom decryption algorithm and inject the decrypted values into HTTP response's statline, headers and body as the result.

        Parameters
        ----------
        plain_response : str
            The received HTTP response in plain format
        iResponseInfo : interface
            A Burp's interface used to retrieve key details about an HTTP response.

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
        
        request_data = {}
        if (operation_mode == IEncryptorDecryptor.MODE_REQUEST_ENCRYPT):
            request_data = self.encrypt_http_request(plain_request, iRequestInfo)
        elif (operation_mode == IEncryptorDecryptor.MODE_REQUEST_DECRYPT):
            request_data = self.decrypt_http_request(plain_request, iRequestInfo)
        else:
            print("WARNING: unknown operation_mode: %s. Request will not be modified." % operation_mode)

        burp_request = self.modify_burp_request(plain_request, iRequestInfo, request_data)
        return burp_request

    def handle_http_response(self, plain_response, iResponseInfo, operation_mode):
        """
        Return an injected/modified HTTP response in raw HTTP format
        """

        response_data = {}
        if (operation_mode == IEncryptorDecryptor.MODE_RESPONSE_ENCRYPT):
            response_data = self.encrypt_http_response(plain_response, iResponseInfo)
        elif (operation_mode == IEncryptorDecryptor.MODE_RESPONSE_DECRYPT):
            response_data = self.decrypt_http_response(plain_response, iResponseInfo)
        else:
            print("WARNING: unknown operation_mode: %s. Response will not be modified." % operation_mode)

        burp_request = self.modify_burp_response(plain_response, iResponseInfo, response_data)
        return burp_request

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
        
        custom_request = IEncryptorDecryptor.build_raw_http(tampered_headers, tampered_body)
        print("Tampered Request", custom_request)

        return custom_request
    
    def modify_burp_response(self, plain_response, iResponseInfo, response_data):
        orig_headers_array = iResponseInfo.getHeaders()

        if len(orig_headers_array) > 0 and response_data['statline']:
            orig_headers_array[0] = response_data['statline']

        tampered_body = response_data['body']
        tampered_headers = orig_headers_array
        for key, value in response_data['headers'].items():
            h_change_index = FloydsHelpers.index_containing_substring(tampered_headers, key)
            header = "%s: %s" % (key, value, )

            if (h_change_index):
                tampered_headers[h_change_index] = header
            else:
                tampered_headers.append(header)
        
        custom_response = IEncryptorDecryptor.build_raw_http(tampered_headers, tampered_body)
        print("Tampered Response", custom_response)

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
    def get_http_body(plain, iReqResInfo):
        req_body = plain[iReqResInfo.getBodyOffset():]
        return req_body

class BrimoEncryptorDecryptor(IEncryptorDecryptor):
    def __init__(self, secret_phrase, device_id, aes_key):
        self.increment = 0
        self.DEVICE_ID_KEY = b64decode(device_id.encode())
        self.STRING_PHRASE = hashlib.md5(secret_phrase.encode()).digest()
        self.KEY = aes_key.encode('utf-8')
        self.GCM_TAG_LENGTH = 16;
    
    def encrypt_http_request(self, plain_request, iRequestInfo):
        orig_headers_array = iRequestInfo.getHeaders()
        x_random_key = [x for x in orig_headers_array if 'x-random-key' in x.lower()][0]
        x_random_key = x_random_key.split(":")[1].strip()

        req_uri = IEncryptorDecryptor.get_request_uri(iRequestInfo)
        req_method = IEncryptorDecryptor.get_request_method(iRequestInfo)
        req_body = IEncryptorDecryptor.get_http_body(plain_request, iRequestInfo)

        bodyparts = req_body.split('request=')
        body = bodyparts[1].strip()

        print("Body", body)
        print("X-Random-Key", x_random_key)

        aesKey = SecretKeySpec(self.KEY, "AES")
        gcmSpec = GCMParameterSpec(self.GCM_TAG_LENGTH * 8, self.saved_nonce)
        cipher = Cipher.getInstance("AES/GCM/NOPADDING")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec)

        encrypted = cipher.doFinal(body.decode())
        encrypted = encrypted.tostring()
        encrypted = b64encode(encrypted)
        integrity_check = hashlib.md5(encrypted).hexdigest().encode()

        full_request = quote_plus((integrity_check + encrypted).decode())
        print("Encrypted Request", encrypted)
        print("Full Request", full_request)

        nonce = full_request[16:32]
        aesKey = SecretKeySpec(self.KEY, "AES")
        gcmSpec = GCMParameterSpec(self.GCM_TAG_LENGTH * 8, nonce)
        cipher = Cipher.getInstance("AES/GCM/NOPADDING")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec)

        new_nonce = cipher.doFinal(str(self.saved_increment).encode())
        new_nonce = new_nonce.tostring()
        new_nonce = b64encode(new_nonce).decode()

        x_random_key = new_nonce

        return {
            "headers": {
                "X-Random-Key": x_random_key
            },
            "body": "request=%s" % full_request
        }

    def decrypt_http_request(self, plain_request, iRequestInfo):
        orig_headers_array = iRequestInfo.getHeaders()
        x_random_key = [x for x in orig_headers_array if 'x-random-key' in x.lower()][0]
        x_random_key = x_random_key.split(":")[1].strip()

        req_uri = IEncryptorDecryptor.get_request_uri(iRequestInfo)
        req_method = IEncryptorDecryptor.get_request_method(iRequestInfo)
        req_body = IEncryptorDecryptor.get_http_body(plain_request, iRequestInfo)

        bodyparts = req_body.split('request=')
        body = bodyparts[1].strip()

        print("Body", body)
        print("X-Random-Key", x_random_key)

        nonce = body[16:32]
        ct = b64decode(unquote(x_random_key))

        aesKey = SecretKeySpec(self.KEY, "AES")
        aesIV = IvParameterSpec(nonce.encode())
        cipher = Cipher.getInstance("AES/GCM/NOPADDING")
        cipher.init(Cipher.DECRYPT_MODE, aesKey, aesIV)
        
        increment = cipher.doFinal(ct)
        increment = increment.tostring()

        nonce = "0" * (16 - 4 - len(increment))
        nonce += increment + "FFFF"
        print("Nonce", nonce)

        ct = b64decode(unquote(body[32:]))
        print("CT", ct, len(ct))

        aesKey = SecretKeySpec(self.KEY, "AES")
        gcmSpec = GCMParameterSpec(self.GCM_TAG_LENGTH * 8, nonce)
        cipher = Cipher.getInstance("AES/GCM/NOPADDING")
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)

        plain = cipher.doFinal(ct)
        plain = plain.tostring()
        print("Plain Request", plain)

        # Save the nonce for request re-encryption in the later stage.
        self.saved_nonce = nonce
        print("Saved Nonce", self.saved_nonce)
        self.saved_increment = increment
        print("Saved Increment", self.saved_increment)

        return {
            "headers": {},
            "body": "request=%s" % plain
        }

    def decrypt_http_response(self, plain_response, iResponseInfo):
        res_body = IEncryptorDecryptor.get_http_body(plain_response, iResponseInfo)
        res_body_cleaned = res_body.replace('"', '')
        print("Response Body", res_body_cleaned)

        nonce = res_body_cleaned[:8] + ('0' * (16 - 8 - len(self.saved_increment))) + self.saved_increment
        print("Decryption Nonce", nonce)

        ct = b64decode(unquote(res_body_cleaned[32:]))
        print("CT", ct)
       
        aesKey = SecretKeySpec(self.KEY, "AES")
        gcmSpec = GCMParameterSpec(self.GCM_TAG_LENGTH * 8, nonce)
        cipher = Cipher.getInstance("AES/GCM/NOPADDING")
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)

        plain = cipher.doFinal(ct)
        plain = plain.tostring()
        print("Plain Response", plain)

        return {
            "statline": "",
            "headers": {},
            "body": res_body
        }

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IMessageEditorTabFactory):
    HTTP_HANDLER = 0
    PROXY_HANDLER = 1

    def __init__(self):
        # Create a new instance of your EncryptorDecryptor class here.
        encdec = BrimoEncryptorDecryptor(
            secret_phrase="fahrdrgr",
            device_id="KOJ3zSW5PCI3jerRaqUISGQ/rf19l3Zm8/5Nxageu5jELHgUsDtiBoAR0FVSRnSt",
            aes_key="c9260f0438183ef64fc6b6231ebf2115"
        )
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
        print("MessageInfo", messageInfo)
        if not iRequestInfo.getUrl():
            print("iRequestInfo.getUrl() returned None, so bailing out of analyzing this request")
            return
        if not self._callbacks.isInScope(iRequestInfo.getUrl()):
            print(iRequestInfo.getUrl(), " is not in scope")
            return
        
        if messageIsRequest:
            plain_request = FloydsHelpers.jb2ps(messageInfo.getRequest())
            iRequestInfo = self._helpers.analyzeRequest(messageInfo)
            print("Original Request", plain_request)

            # 1. Request Decryption Stage
            # If the message is a HTTP request and the handler is iProxyListener,
            # Then Plainmaker will decrypt the HTTP request so the user can view/edit them in their plaintext form before forwarding it to the destination server.
            if handler == self.PROXY_HANDLER:
                print("1. Request Decryption Stage")

                new_req = self.encdec.handle_http_request(
                    plain_request, 
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
                    plain_request, 
                    iRequestInfo, 
                    operation_mode=IEncryptorDecryptor.MODE_REQUEST_ENCRYPT
                )
                new_req_bytes = FloydsHelpers.ps2jb(new_req)
                messageInfo.setRequest(new_req_bytes)
        else:
            plain_response = FloydsHelpers.jb2ps(messageInfo.getResponse())
            iResponseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
            print("Original Response", plain_response)

            # 3. Response Decryption Stage
            # If the message is HTTP response and the handler is iHttpListener, 
            # Then Plainmaker will decrypt the HTTP response so user can view/edit them in their plaintext form before forwarding it to the client.
            if handler == self.HTTP_HANDLER:
                print("3. Response Decryption Stage")

                new_res = self.encdec.handle_http_response(
                    plain_response, 
                    iResponseInfo, 
                    operation_mode=IEncryptorDecryptor.MODE_RESPONSE_DECRYPT
                )

                print("New Res", new_res)
                new_res_bytes = FloydsHelpers.ps2jb(new_res)
                messageInfo.setResponse(new_res_bytes)
                
            # 4. Response Re-encryption Stage
            # If the message is HTTP response and the handler is iProxyListener,
            # Then Plainmaker will encrypt the HTTP response so that the client still receives a valid (encrypted) HTTP response payload.
            else:
                print("4. Response Re-encryption Stage")
                return
                new_res = self.encdec.handle_http_response(
                    plain_response, 
                    iResponseInfo, 
                    operation_mode=IEncryptorDecryptor.MODE_RESPONSE_ENCRYPT
                )
                new_res_bytes = FloydsHelpers.ps2jb(new_res)
                messageInfo.setResponse(new_res_bytes)

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
        for index, x in enumerate(headers):
            if "content-length:" == x[:len("content-length:")].lower():
                headers[index] = x[:len("content-length:")] + " " + str(length)
                return newline.join(headers)
        else:
            print("WARNING: Couldn't find Content-Length header in request, simply adding this header")
            headers.insert(1, "Content-Length: " + str(length))
            return newline.join(headers)