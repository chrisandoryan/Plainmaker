from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IBurpExtenderCallbacks

from datetime import datetime
import hmac
import json
import base64
import hashlib
from urlparse import urlparse
from urllib import unquote
from base64 import b64encode, b64decode

NAME = "Plainmaker - BRI Senyum"

class IEncryptorDecryptor():
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

    def handle_http_request(self, plain_request, iRequestInfo):
        """
        Return an tampered/injected/modified HTTP request in raw HTTP format
        """

        req_method = self.get_request_method(iRequestInfo)
        req_uri = self.get_request_uri(iRequestInfo)
        
        req_data = self.encrypt_decrypt_on_http_request(req_uri, req_method)
        request = self.construct_tampered_request(plain_request, iRequestInfo, req_data)
        
        return request

    def handle_http_response(self):
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

class SenyumEncryptorDecryptor(IEncryptorDecryptor):
    def __init__(self, code_challenge, auth_token, x_auth_token):
        self.CODE_CHALLENGE = code_challenge
        self.AUTH_TOKEN = auth_token
        self.X_AUTH_TOKEN = x_auth_token
        
    def encrypt_decrypt_on_http_request(self, uri, body="", timestamp=None, method="POST"):        
        v = uri
        x = method.upper()

        T = self.AUTH_TOKEN
        k = datetime.utcnow().isoformat()[:-3]+'Z' if not timestamp else timestamp
        json_body = json.dumps(body, indent=None, separators=(',', ':')) if body else ''

        message = 'path=' + v + '&verb=' + x + '&token=Bearer ' + T + '&timestamp=' + k + '&body=' + json_body
        
        h = hmac.new(self.CODE_CHALLENGE.encode(), message.encode(), hashlib.sha256)
        signature = base64.b64encode(h.digest())
        
        return {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Linux; Android 8.1.0; Hisense U964) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Mobile Safari/537.36",
                "x-authorization": "Bearer %s" % self.X_AUTH_TOKEN,
                "authorization": "Bearer %s" % T,
                "bri-timestamp": k,
                "bri-signature": signature,
                "host": "sandbox.outer.api.bri.co.id",
                "Content-Type": "application/json",
            },
            "body": json_body
        }

    def handle_http_request(self, plain_request, iRequestInfo):
        req_uri = IEncryptorDecryptor.get_request_uri(iRequestInfo)
        req_method = IEncryptorDecryptor.get_request_method(iRequestInfo)
        req_body = IEncryptorDecryptor.get_request_body(plain_request, iRequestInfo)

        req_data = self.encrypt_decrypt_on_http_request(uri=req_uri, body=req_body, method=req_method)
        return self.construct_tampered_request(plain_request, iRequestInfo, req_data)
        
    def handle_http_response(self):
        return super().handle_http_response()

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

            encdec = SenyumEncryptorDecryptor(
                code_challenge="7A6S7cTGrNLwWsMcXAdySTM3sRM8ECjHiWsKhXvFS2o",
                auth_token="GFrdtruE4Ac6jLRYk0OR6QGKmjhc",
                x_auth_token="Bearer eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo0MDk2LCJwMnMiOiJaalV3WldFeE1qY3RNelkzTkMwME1UVTVMV0ZrT0RFdFpqZG1aVGN3T0RSa1l6Wm0ifQ.V6X84Vh6zlhWQYsaIZ_Ji5OceXWhTBTa_bU59Wfps_7xvjzh6Sp85w.dIJdZmnNnSNbQD53EtkLpA.bS73YmhhuIFYCIS3_682Wc1-eoTKnnyiw2PuRe4zT0zqycYq6vPodfKpzCQHLLorTpokSCIGCLTk4qLC-k-KA02E0Vy6jdLmyw5m_juAItpW--2MB1MQ-EqlAblpAFz9Jnng-5VAVj66zsaRX_X3HPqX7HYfqtcVUU4sXFqtkByE1Tp5pnchXIGAY32_7PSHzmrjHBYPgMZlpSn6HGR7wbIte8g2ahXf4VUNT_u1mwuN90pXzP2htACs4FquYTlkxzfX11yNfZdbQOyMizEokcluyqpLO4untIvrJhxjXbn3h1cLtICfi0g5yt1Waefn_tAIUkFbkd6_X0iAKUHBQQNJ8avspZmAIpl862zgzxvxU8qm7eHHT91G5y7gZ07h8RdLekPvq1IOQ3QbCV49JkRBrpg04dOOm1AGn7AlLKL_ub8K3AK2Y3wIM8a8DzwOItnG5XoTz78b1gTO_kGtqthI5l6HNSRkHBuXQXBg0On57sJNn7fqQi59NRUCb2zlVvdevnI4ibAI0Xjw8fdsNo5TWwXQe21xNJNMxeShRpWZydg6CnKswgkHLHnE940YUfrnnydF0R7fUHtWQJaEz4OkGN_74c14QH5CjdbNTLNqQE83ECA7hBNHtM44a3JuNiHllUyGXxsKFDefdvlwyeb3xeiVzZYHTxR4c8l2-5PdV8l6cw1XGF4m-mSF_UsWO2xVUkZB2hKKpkjw83JUrZj_nD2Pvka4iq_nzupng0dUhKcqHpK_BRG7ori22pCK0Nd0rYZfpK375GUeg5kjKseCyTDKmeaw7nRBN4MKK63bUYQd55_2oZYfikEqugzWzNgTN1g4M83h7ovXfT_ak3Yt1B-i117l6N8MgO4mdbgeY1n0R19C9aeIHaxi4I6yGBHbNWzZ5MG6JWDMNG0pDFAFpvLs7vnOEVx7UwDsQUTs7LMLsvcHw3vllurBwrCT8oXwkcp6PrPAfSichY_2ShhJUlhXh8aev6_GD8xg28eDP7fJ2d_rGUOX6Pft4TnUpc4YTwgd7PZjB4vvOE_u5Urp1dkzQ-v_b1YARnvAi-blC-YoDgPBzMZHaT8ADiGUAPEEaAAv4cVQ3SUmZVLt1No3fty2ijT8iQ5_kxBTrfsyL_b6SgRW4hIMFtAlNJOI8hXZP2ydDddZgrSsvSvMPXrwJ9L0pzmavivKoAG8WxjHIH8UqbE-u5E0fz1rqPFKR1SvUaipxkcU0feXLf2Jtgx6T_qGjmWcyeb3yAgU9X1ZhQ-KM4-AOpYmbZ6RQ77lO3bq3vlxQbMNTHh4ZB4cCWITO5NgI9Gjypa-FjEEb0hLmzXWTgvScp_2x8J3U6-CphnHqJbgE-xYy696PN2JqPJWVxjjCciXEBFl-FZSZ7rJmYeKk7EjZNzRTHuiTOfzCoav03h1EUF2ZwgyrGm0Ifdk1-4R8WnEh-8b2veyWVb-N85od5V-jzsms5FteC7Leomsii3y8YiGC2oxE8NyzvFaYp-rVjj1uhEf7VOFG9-frlzCIFSUc5uWHMdwwcsNmepFrWkWh_Dtc0gWJl5cFsYQb2kEQBqm8KA_-FSGaSHhs-dB9b0ijlPJ8VYIKRVAFuKv84M3xAITeAcHH41yc5CL8zWuENzkqdgIDdmYX-zEwRyWKD6YoMzStgrcvoz09t6c5gKw-SpVSgFpXho8BsCItO5tb18R3XtM71RQtTxuy1hmDkN59BV8P-AN3KNyaf0164AIPtcMhKOI0s_c281LDtzme4PYbs5hD0Su2dKQnTCZCEhfRKCulxujhhtU2g3vx8WkLZhzqbdU-SukMs84_0MIGJ6jjF6aVs4pDaO1NdK2hix1mK-WGffq7CF0IeR9jIE6DrjlWShHGlYuOnpSAAf2_VqESs4NiDs7nDoOjPU8kjley0EKD93OscfNJiLykgNcKAGvuYTgD5aePshuNoVr_dNtCbANTZytPAX3Rvt8ErHhdgA6rxzNHAVYqkns7T_RQS5I0InEarF-cGpI0ujHpazwo9Jc65y077T1jr4bXOSUn7W5lceGxDFOVPt0j5Tt7cM8cl2IYKf48R6kdseKI3RXcotjpTofvz5AIcETho2IqQkbOQgE8xroExpiZFvwbFzXEHVDn8qOHHp69rMOjboMJ5mj2TxiQcZS7m6cK5SxbUDGZtAei0QF6mgJa69MREhAoMNkB6g1onOyX3BXICvf6bEo1qz-AKEDEfJFjpa0hcfoeDyL9E7UWEt2PBWjecwWUBuYAJzVSxYcb7UwsB6H3yGfrTXXJqZOK2Ll63G6vjeI67I3BKFUAful2gRlTcRsSDbd2d2T4hHx08HVSSgMpcQzL3IfBhpIUnIJyXjqjvknti9NR13mVR80PfQCYZJIzCyTJO8aBhujsuL4o7k1alLxWQOMe-P26mVw0hVHBSHfsuyysn7mJSXX6yutJZk3BI2P6xYfCtI1nHkVeElYRVqR3ulfrL8YY5EB7ur0RdTh2lROfPe41BYZwHWcI1hi6nXQKmMr0MqG6jWPEvYUSYItMhFgXVf51qYSNQ-pSo2GUlD-q5sdSur4eklHZjro5zazGYh0vnPVGi-90gAN9bH0izUfk8lS0lvyHiBn6DPgMO6lXJueaImb1PYc0OARxVfXeebCCZAe3hJHf51NjOjVGiOcGjUDyjVTs8WBhBPh86Ztf1j21hKdJvsYyLH3cKka0qh6J-rgn8LZvfo6Xf3HG3gulQs1lLO-sakgtNo9BdoF6sxz1Yvjd-lDdrC66yOks_bedIUnyzAbRFDRrBxqSE1mKxInz1O-2dLOMsnVNyw2nIqiapHjfmYn5KO1bojXTe_GoPOKozKVxVV_GO51IjZvyTR7q71oUferUETGkIIJtfkGi9qUpaU2TBaDsfSEYy4KZR1dQEs0dCyj4WRva5KHWn63ZBVfKTKZRUNP_j0qiP8_lQ-KxUKMpTIP4HtZ8rvxBY5ARIvywmDJwZUgxYB95yNLQGSPgWCcj0E2oLhlhWHnvsdZ8GFkDaYvjrJ4RcKVAPF6XidbjeM_iVua5uehBmZ_iLEX-O1oaqspeBG9O-B8Iush1xZVJDICXn_uVKOSvVXHcObLipXaLkXuedvvztcz6qpvg_n6FNdAkpUHhFd6KKtGsAkodupggefPpXGT0R5YymRyQ9ZoYb7K7KPjy7Q0qhcQv3vDkk1Ewda7QtJGulgORde8p7sfIpzZuavk7PXA0Jfin8Oqq9w1Wq-sjw6vOmJFdJkiA4frwDb3fgotCQeQJ2dMoAnPyv6HettGbO3Bul-0aygrSVhapyLwv0w4d2c7fMbfA6DlV0t3rvLl751-K-BJAS5YW9noig8IfoQQ0rYn1enpJj1QrfF8HFQ74mgkcdcgMySQRC_fIK0IcUTgCo97ce03PBo3IyjmOYGmkOOM7utXJOok-7yd6Z8rkEErW7RxvY0AeJMpmAP9jZTaciWK6IsA8x0gXc0FHKwazjUPZP5rdd40InkFLWaIt40NHNyUkxoqWuKOTBx-93-yjcrz9jBgLgseL3btO2P3I6-_jvV9327gFVhzcgV-TbNcAScEVaheCL6ufiWW_pntbhmrBCXgT1N9lzyo7-WyENkuN0cnvKC-5ewSRxB27dYC-SeUddl0gxutB8kSwrkS0vt6MFSGIoiCCrMVLzkK71mLGajNpgdOGGlQY7Nnlh0oPZil4Tca_YX3gYdI3YRSvTjItkIG_I7mR2k1F0U1OWXnK2_8RglIL00ZbsJPVV09PwDaSQj6eWDapq-WvA0eNSVIr2E-jx4L35f7B0li2U1OfcZFTG7NkF_UcsI1hGgKapYMo1jqNshT6-gW72OqxlZ2-cLDmHJq7K-KzcMjl-brzIAbRbfj0QaQwHIlhpbII1cxcVXcMxpuJB59zZ__024gL56fbr-bxGWl4Yy-Ph4XcUGecZEh_3-_BYBU5Li7WJ18wiqTfo3RcVHOFaq-iSZBsH8tI6kfrT1j7gaYbxe4dEIIj6bcDljfz6Ki0giZz1xhymvemm3RZwKA15-ClAGwwFyg5JAyzJSQDwis37A30TYenGz4VKO6nu84Ti0Zts-HS2tR8gQT1UuYcf45KwkgBEA8VKO-0f6J9YooRcVWwXG2w29cVHrwdFbSNv3TompKwKBKK_WrnEeRJlwZCuNF-0E8CaSN0vQjrv8jnNnbNGHHzFRt-TtGJqX_F_E_kROnLZdHkYgGn7hjQJ4V5QCfhX3pfhRDbmOqyRnWGdRtMAegTxLNNV60MfCjnuc5DHQIn3BpBDtk2I30zIx9BW8zN-qiuhegY25oZWAZnMA6XeIZArYT76t6RCjHkewIkNTZLywkUzbCoeqqyni56ZaHyFaXnhgHlzAYPEzXNR3UYTUercHnimnz_w4nHb_hKzYC77NRUEd6_7J0csJNcnMLg8gFrwKnShK2RUCp4R1kX_5liZglBQz0o53Iumk0jrkzUf_Uo50GNR5VH4BU91a_2jw6k1TuO5LGQOxKgJAAFPjjDLAo5FbrPj34j4o27dGXmE82kAATsATawWpWOldpth3ZZRq6Zdmp5W0ojG8EZeCh4mDZyXUIFrHEI6Q6EvqgRU40PYDYvyGvrPH6y2StWSip0HgoDAwFHoPi48ce_jKnPOfz9DIZjcbMy535mAf4HzHR6IPJ8QnRANztYeTyk5NPWwa1poJhiS3mxr8N6-rv-31tJA8CTsEonRP--bBCnPwdWZchIP_JAt9As47by8NbYvBRpBC8A6HQRSiqQhOg-8jB_OMU17_RsShyuO-xSCRmN-1uCu2Y58b4U8zS6W8D26XelzE-zCCoslYJy7gqt1jL6H38eUdRP49V2efhD7_9mq7yu2ynO2wm7EYvKknKG0nYXK-AiqxhNIDWnCz3rp8_LNyVuLTOPGuW38NiJg7s6Gxbyj9fbl8C-64o2aSvvTA45ZudKxLDQUG2WQ7E6gyp4gB7Kd2f72JERJ8dtInZmkceP3oYUJ02Q5XgifdWmrLSIjeR-jqhaqXjakkMEsRPNqM8WEbCSS3z2W19XZR99eTkQ7wzs8goAb-Gtq8uj2uW4Kr_tjJR3Oa6hXYKrZyXRDTNPkSsDwxLidFusee_2oJHwnKD9L4Lidg_Eq7xhsbZxroR2xNayJrZozbM6D3XxHM2udH_fXnDLUpwRgk_eGoPxeq0qAczXUbyOKtJ86ssGJsePbSbrHdf8Z-ziP2iM-exUQoikIRv5bxi7p2SSLuKz9J2cSOMR2zR_12OhZz9wV-QDB4b0sXweqNH3O3RQ4eRe6xPRujmEl2yfnAdOYGPjAvhUi-u7BVuzsCtCziemuTumVPlsE1nG5-E3bkT7cqaLNUmhIG1Wnd5VLU9c_toRzLMhnjFt5zzWxY3n6zChMfe7mWyOCJprPC68TlcSOzCN-4eLPISik6Qh5p6LSb2DqAZlAXBihGu0I2UMp2YxRAlQV5BjyrTcavsW7ZJHh9FzhF1fPFKv-Txyyaf0S0jlJjbPpjxzpzOwMjn5CsFz615uG1gWXNHPm9Gfsn9LJb3Y2V-diEiCsERH_0pWMPdDGukNjOYjibAn2jf7L_eg1Zci5Dhhv1pjkqej-l_3-y8ut2w5hZ_tGh_-1VX_qBhvspmd5-Nm1s4YA0D8eYKocVR31xMgflKlSwlF7hLi50fxD-UrHSQ4-MKLAcZ2QsN2CQq47v6Iqsi3YqXkR6FBRlfS5o6iDZkaqgSoBaGfxrlT3Q.8RcQenaHOkydf0ozwutlrQ"
            )

            new_req = encdec.handle_http_request(plain_request, iRequestInfo)
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