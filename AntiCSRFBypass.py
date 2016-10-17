'''
Anti-CSRF Bypass is a simple Burp extension which helps you to update CSRF tokens in
requests sent by Burp tools. It does so by extracting a new and valid token from the
headers or body of a macro response and replacing the original token in the current
request.
'''

__description__ = 'Anti-CSRF bypass plugin for Burp Suite'
__author__ = 'Gabor Seljan'
__version__ = '0.1'
__date__ = '2016/10/09'

import re

from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import IParameter

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('Anti-CSRF Bypass')
        callbacks.registerSessionHandlingAction(self)

    def getActionName(self):
        return 'Bypass Anti-CSRF'

    def performAction(self, currentRequest, macroItems):
        requestInfo = self._helpers.analyzeRequest(currentRequest)

        response = macroItems[0].getResponse()
        responseInfo = self._helpers.analyzeResponse(response)
        responseHeaders = str(responseInfo.getHeaders()).splitlines()
        responseBody = self._helpers.bytesToString(response)[responseInfo.getBodyOffset():]

        token = None

        # Get token from response header
        for responseHeader in responseHeaders:
            if responseHeader.startswith('X-CSRF-TOKEN'):
                token = responseHeader[responseHeader.index(':')+2:]
                break

        # Or get token from response body
        match = re.search('csrf_token":"(.*)"', responseBody)
        if match:
            token = match.group(1)

        # Update token in request header
        if token:
            requestHeaders = requestInfo.getHeaders()
            for i in range(len(requestHeaders)):
                requestHeader = str(requestHeaders[i])
                if requestHeader.startswith('X-CSRF-TOKEN'):
                    requestHeaders[i] = 'X-CSRF-TOKEN: %s' % token
                    break

            requestBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
            httpMessage = self._helpers.buildHttpMessage(requestHeaders, requestBody)
            currentRequest.setRequest(httpMessage)
