import re
from flask import Flask, request, abort

app = Flask(__name__)

# Define regular expressions to detect malicious requests
sql_injection_pattern = re.compile(r'\b(union|select|and|or|from|where)\b', re.IGNORECASE)
xss_pattern = re.compile(r'<script|<iframe|<img|<svg|<body|<embed|<video|<audio', re.IGNORECASE)

@app.before_request
def block_malicious_requests():
    # Check if the request method is POST
    if request.method == 'POST':
        # Check if the request body contains malicious SQL injection keywords
        if sql_injection_pattern.search(request.get_data(as_text=True)):
            abort(400, 'Malicious SQL injection request detected')

        # Check if the request body contains malicious cross-site scripting (XSS) keywords
        if xss_pattern.search(request.get_data(as_text=True)):
            abort(400, 'Malicious cross-site scripting (XSS) request detected')

if __name__ == '__main__':
    app.run(debug=True)