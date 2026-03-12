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

        callbacks.setExtensionName("JSON traceable to Burp Request")

        # ===== UI =====

        self.panel = JPanel()
        self.panel.setLayout(BorderLayout())

        self.inputArea = JTextArea(15, 80)
        self.outputArea = JTextArea(15, 80)

        self.methodBox = JComboBox(["AUTO", "GET", "POST"])

        # default = checked
        self.sendRepeater = JCheckBox("Send to Repeater", True)

        startButton = JButton("Start", actionPerformed=self.convert)

        topPanel = JPanel()
        topPanel.add(JLabel("Method:"))
        topPanel.add(self.methodBox)
        topPanel.add(self.sendRepeater)
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

            # ===== Query handling =====

            query = parsed.query

            if queryParams:

                queryString = urlencode(queryParams)

                if query:
                    query = query + "&" + queryString
                else:
                    query = queryString

            if query:
                path = path + "?" + query

            # ===== Method detection =====

            method = str(self.methodBox.getSelectedItem())

            if method == "AUTO":
                method = "POST" if body else "GET"

            # ===== Build request =====

            request = method + " " + path + " HTTP/1.1\n"
            request += "Host: " + host + "\n"

            for k, v in headers.items():

                if k.lower() != "host":
                    request += k + ": " + str(v) + "\n"

            request += "\n"

            # ===== Body handling =====

            if body:

                if isinstance(body, dict):

                    body = json.dumps(body)

                request += body

            self.outputArea.setText(request)

            # ===== Send to Repeater =====

            if self.sendRepeater.isSelected():

                port = 443
                https = True

                if ":" in host:

                    hostParts = host.split(":")
                    host = hostParts[0]
                    port = int(hostParts[1])

                self.callbacks.sendToRepeater(
                    host,
                    port,
                    https,
                    request.encode(),
                    None
                )

        except Exception as e:

            self.outputArea.setText("Error: " + str(e))