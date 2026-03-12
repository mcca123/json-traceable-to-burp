JSON to Burp Request Converter
==============================

This Burp Suite extension converts JSON-formatted HTTP request data into
a raw HTTP request that can be used directly in Burp Suite tools such as
Repeater.

The extension is designed to simplify the process of converting structured
request data (such as logs or captured JSON requests) into a format that
Burp can send.

Features
--------

- Convert JSON request format to raw HTTP request
- Supports GET and POST methods
- AUTO method detection (based on request body)
- Supports query parameters (queryParams)
- Supports JSON body and string body
- Dynamic header handling
- Optional automatic "Send to Repeater"
- Simple UI inside Burp Suite

Supported JSON Format
---------------------

The extension expects JSON input similar to the following format:

{
  "uri": "https://example.com/api/search",
  "queryParams": {
    "key": "test",
    "page": 1
  },
  "headers": {
    "authorization": "Bearer token",
    "accept": "*/*"
  },
  "cookies": {},
  "body": "testA=1"
}

Example Output
--------------

GET /api/search?key=test&page=1 HTTP/1.1
Host: example.com
authorization: Bearer token
accept: */*

testA=1

Installation
------------

1. Download Jython standalone:
   https://www.jython.org/download

2. In Burp Suite:
   Extender → Options → Python Environment

3. Set the path to:
   jython-standalone-2.7.x.jar

4. Load the extension:
   Extender → Extensions → Add

5. Select:
   Extension type: Python

6. Choose:
   json_to_burp.py

7. Click Next to load the extension.

Usage
-----

1. Open the "JSON Request" tab in Burp.
2. Paste the JSON request into the input area.
3. Select the HTTP method (AUTO / GET / POST).
4. Enable or disable "Send to Repeater".
5. Click "Start" to convert the request.

The converted raw HTTP request will appear in the output area.

If "Send to Repeater" is enabled, the request will automatically be sent
to Burp Repeater.

Notes
-----

- queryParams will be automatically converted to URL query strings.
- JSON body objects will be automatically serialized.
- The Host header will be generated from the URI.

Requirements
------------

- Burp Suite
- Jython 2.7

Author
------

It's me "Chatuphon Chalitthikun"

Custom Burp Extension for JSON request conversion.