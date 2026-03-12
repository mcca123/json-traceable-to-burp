# -*- coding: utf-8 -*-

from burp import IBurpExtender, ITab
import json

from java.awt import BorderLayout
from javax.swing import (
    JPanel, JTextArea, JButton, JScrollPane,
    JComboBox, JCheckBox, JLabel
)

from urlparse import urlparse
from urllib import urlencode


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):

        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        callbacks.setExtensionName("JSON to Burp Request")

        # ===== UI =====

        self.panel = JPanel()
        self.panel.setLayout(BorderLayout())

        self.inputArea = JTextArea(15, 80)
        self.outputArea = JTextArea(15, 80)

        self.methodBox = JComboBox(["AUTO", "GET", "POST"])

        # default checked
        self.sendRepeater = JCheckBox("Send to Repeater", True)

        # ===== NEW CHECKBOXES =====
        self.useForwardedPrefix = JCheckBox("Use x-forwarded-prefix", False)
        self.useForwardedPath = JCheckBox("Use x-forwarded-path", False)

        startButton = JButton("Start", actionPerformed=self.convert)

        topPanel = JPanel()
        topPanel.add(JLabel("Method:"))
        topPanel.add(self.methodBox)
        topPanel.add(self.sendRepeater)

        # add new options
        topPanel.add(self.useForwardedPrefix)
        topPanel.add(self.useForwardedPath)

        topPanel.add(startButton)

        self.panel.add(topPanel, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.inputArea), BorderLayout.CENTER)
        self.panel.add(JScrollPane(self.outputArea), BorderLayout.SOUTH)

        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "JSON Request"

    def getUiComponent(self):
        return self.panel

    # ===== Convert Logic =====

    def convert(self, event):

        try:

            data = json.loads(self.inputArea.getText())

            uri = data.get("uri")
            headers = data.get("headers", {})
            body = data.get("body")
            queryParams = data.get("queryParams")

            parsed = urlparse(uri)

            host = parsed.netloc
            path = parsed.path

            # ===== sanitize path =====

            path = path.strip().replace("\n", "").replace("\r", "")

            # ===== query handling =====

            query = parsed.query

            if queryParams:

                queryString = urlencode(queryParams)

                if query:
                    query = query + "&" + queryString
                else:
                    query = queryString

            if query:
                path = path + "?" + query

            # ===== forwarded prefix/path logic =====

            if self.useForwardedPath.isSelected():

                forwardedPath = headers.get("x-forwarded-path")

                if forwardedPath:
                    forwardedPath = forwardedPath.replace("\n", "").replace("\r", "")
                    path = forwardedPath
                    if query:
                        path = path + "?" + query

            elif self.useForwardedPrefix.isSelected():

                prefix = headers.get("x-forwarded-prefix")

                if prefix:
                    prefix = prefix.replace("\n", "").replace("\r", "")
                    if not path.startswith(prefix):
                        path = prefix + path

            # ===== method =====

            method = str(self.methodBox.getSelectedItem())

            if method == "AUTO":
                method = "POST" if body else "GET"

            # ===== headers =====

            headerList = []

            headerList.append(method + " " + path + " HTTP/1.1")
            headerList.append("Host: " + host)

            for k, v in headers.items():

                if k.lower() == "host":
                    continue

                value = str(v).replace("\n", "").replace("\r", "")

                headerList.append(k + ": " + value)

            # ===== body handling =====

            bodyBytes = None

            if body:

                if isinstance(body, dict):
                    body = json.dumps(body)

                body = body.replace("\r\n", "\n")

                bodyBytes = body.encode()

            # ===== build request safely =====

            requestBytes = self.helpers.buildHttpMessage(headerList, bodyBytes)

            # ===== show output =====

            self.outputArea.setText(self.helpers.bytesToString(requestBytes))

            # ===== send to repeater =====

            if self.sendRepeater.isSelected():

                port = 443
                https = True

                if ":" in host:

                    parts = host.split(":")
                    host = parts[0]
                    port = int(parts[1])

                self.callbacks.sendToRepeater(
                    host,
                    port,
                    https,
                    requestBytes,
                    None
                )

        except Exception as e:

            self.outputArea.setText("Error: " + str(e))