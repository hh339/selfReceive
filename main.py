from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key

import base64
import textwrap
import json, time, os

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def create_signature(method, requestURI, clientID, requestTime, requestBody, privateKey):
    constructContent = method + " " + requestURI + "\n" + clientID + "." + requestTime + "." + requestBody

    key_pem = base64.b64decode(privateKey)

    # Load private key
    private_key = load_der_private_key(
        key_pem,
        password=None
    )

    signature = private_key.sign(
        constructContent.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    generated_signature = base64url_encode(signature)
    return generated_signature

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home_page():
    data_set = {'Page':'Home', 'Message':'Successfully'}

    success = 'success'
    return success

@app.route('/receive', methods=['POST'])
def receive_data():
    # Get the JSON data from the request
    data = request.get_json()

    # Print the received JSON data
    print("Received JSON data:\n", data)

    #get value from env
    load_dotenv()

    #get date time now
    now = datetime.now(ZoneInfo("Asia/Kuala_Lumpur"))
    formattedDateTime = now.strftime("%Y%m%d%H%M%S%z")

    #create response
    jsonResponse = "{\"result\": {\"resultCode\": \"SUCCESS\", \"resultStatus\": \"S\",\"resultMessage\": \"success\"}}"

    #get value from env
    clientId = os.getenv("CLIENTID")
    privateKey = os.getenv("RSAENCRYPTKEY")

    #signature
    signature = create_signature("POST", "/receive", clientId, formattedDateTime, jsonResponse, privateKey)

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "response-time": formattedDateTime,
        "client-id": clientId,
        "signature": "algorithm=RSA256,keyVersion=1,signature=" + signature
    }

    # forward response as JSON
    return Response(jsonify(jsonResponse), 200, headers)

if __name__ == "__main__":
    app.run(port=7777, debug=True)