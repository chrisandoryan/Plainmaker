from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IBurpExtenderCallbacks

NAME="Plainmaker"

class IEncryptorDecryptor():

    def get_http_processed_request(self, orig_request: str) -> str:
        """Return a decrypted HTTP request in raw format"""
        pass
    
    def get_http_processed_response(self, orig_response: str) -> str:
        """Return a decrypted raw HTTP response in raw format"""
        pass

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
            print(iRequestInfo.getUrl() + " is not in scope")
            return
        # TODO: Usually there's some kind of marker that indicates if the content is encoded
        search = "content-type: application/octet-stream"
        if messageIsRequest:
            req = FloydsHelpers.jb2ps(messageInfo.getRequest())
            if search in req.lower():
                self.request_body_decode(messageInfo)
        else:
            resp = FloydsHelpers.jb2ps(messageInfo.getResponse())
            if search in resp.lower():
                self.response_body_decode(messageInfo)
        pass



class FloydsHelpers(object):
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