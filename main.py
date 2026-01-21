from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key
import urllib.parse

import base64
import textwrap
import json, time, os, redis
import sys
import requests

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
# from com.alipay.alipayplus.api.tools.constants import *

IS_PYTHON_VERSION_3 = sys.version_info[0] == 3

def __add_start_end(key, startMarker, endMarker):
    if key.find(startMarker) < 0:
        key = startMarker + key
    if key.find(endMarker) < 0:
        key = key + endMarker
    return key

def __fill_private_key_marker(private_key):
    return __add_start_end(private_key, "-----BEGIN RSA PRIVATE KEY-----\n", "\n-----END RSA PRIVATE KEY-----")

def __sign_with_sha256rsa(private_key, sign_content, charset='utf-8'):
    sign_content = sign_content.encode(charset)

    # Convert string to bytes
    private_key_bytes = private_key.encode('utf-8')

    # Load the key
    privKEy = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
    )

    signature = privKEy.sign(
        sign_content,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    base64_url_signature = (
        base64.urlsafe_b64encode(signature)
        .decode()
        .rstrip("=")
    )

    url_encoded_sig = urllib.parse.quote(base64_url_signature)

    return url_encoded_sig

def gen_sign_content(http_method, path, client_id, time_string, content):
    payload = http_method + " " + path + "\n" + client_id + "." + time_string + "." + content
    return payload

def sign(http_method, path, client_id, req_time_str, req_body, merchant_private_key):
    req_content = gen_sign_content(http_method, path, client_id, req_time_str, req_body)
    private_key = __fill_private_key_marker(merchant_private_key)
    sign_value = __sign_with_sha256rsa(private_key, req_content)
    return sign_value

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
    signature = sign("POST", "/receive", clientId, formattedDateTime, jsonResponse, privateKey)

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "response-time": formattedDateTime,
        "client-id": clientId,
        "signature": "algorithm=RSA256,keyVersion=1,signature=" + signature
    }

    # forward response as JSON
    return Response(jsonResponse, 200, headers)

@app.route('/getPaymentCode', methods=['POST'])
def get_payment_code():
    # Get the JSON data from the request
    data = request.get_json()
    region = data["region"]
    customerId = data["customerId"]
    codeQuantity = data["codeQuantity"]
    terminalType = data["terminalType"]
    osType = data["osType"]
    deviceTokenId = data["deviceTokenId"]
    clientIp = data["clientIp"]

    jsonDict = {
        "region": region,
        "customerId": customerId,
        "codeQuantity": codeQuantity,
        "env":{
            "terminalType": terminalType,
            "osType": osType,
            "deviceTokenId": deviceTokenId,
            "clientIp": clientIp
        },
    }

    jsonResponse = json.dumps(jsonDict)

    #get value from env
    load_dotenv()

    #get value from env
    clientId = os.getenv("CLIENTID")
    privateKey = os.getenv("RSAENCRYPTKEY")

    #get date time now
    now = datetime.now(ZoneInfo("Asia/Kuala_Lumpur"))
    formattedDateTime = now.strftime("%Y%m%d%H%M%S%z")

    print(jsonResponse)

    #signature
    signature = sign("POST", "/aps/api/v1/codes/getPaymentCode", clientId, formattedDateTime, jsonResponse, privateKey)

    #sending url
    url = "https://open-sea-global.alipayplus.com/aps/api/v1/codes/getPaymentCode"

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "request-time": formattedDateTime,
        "client-id": clientId,
        "signature": "algorithm=RSA256,keyVersion=1,signature=" + signature
    }

    response = requests.post(
        url,
        headers=headers,
        # data=jsonResponse,     # use data, not json
        json=jsonDict,
        timeout=10
    )

    print(response)

    return Response(response, 200)

@app.route('/pay', methods=['POST'])
def pay():
    # Get the JSON data from the request
    data = request.get_json()
    paymentAmountValue = (data.get("paymentAmount", {}).get("value", ""))
    paymentAmountCurrency = (data.get("paymentAmount", {}).get("currency", ""))
    payToAmountValue = (data.get("payToAmount", {}).get("value", ""))
    payToAmountCurrency = (data.get("payToAmount", {}).get("currency", ""))
    paymentRequestId = data.get("paymentRequestId", "")

    print(paymentAmountValue)
    print(paymentAmountCurrency)
    print(payToAmountValue)
    print(payToAmountCurrency)
    print(paymentRequestId)

    #get value from env
    load_dotenv()

    #get value from env
    clientId = os.getenv("CLIENTID")
    privateKey = os.getenv("RSAENCRYPTKEY")

    #redis
    r = redis.Redis.from_url(os.environ.get('REDIS_URL'),decode_responses=True)

    #check if paymentID in redis
    if not r.exists(paymentRequestId):
        print("not exist")
        paymentId = datetime.now(ZoneInfo("Asia/Kuala_Lumpur")).strftime("%Y%m%d%H%M%S")
        paymentTime = datetime.now(ZoneInfo("Asia/Kuala_Lumpur")).isoformat(timespec="seconds")
        save = paymentId + "|" + paymentTime + "|" + paymentAmountValue + "|" + paymentAmountCurrency + "|" + payToAmountValue + "|" + payToAmountCurrency
        r.set(paymentRequestId, save)
    else:
        print("exist")
        saved = r.get(paymentRequestId)
        savedSplited = saved.split('|')
        paymentId = savedSplited[0]
        paymentTime = savedSplited[1]

    formattedDateTime = datetime.now(ZoneInfo("Asia/Kuala_Lumpur")).strftime("%Y%m%d%H%M%S%z")

    jsonDict = {
        "result":{
            "resultCode": "SUCCESS",
            "resultStatus": "S",
            "resultMessage": "success"
        },
        "paymentId": paymentId,
        "customerId": "1234567890123456",
        "paymentTime": paymentTime
    }

    jsonResponse = json.dumps(jsonDict)

    #signature
    signature = sign("POST", "/pay", clientId, formattedDateTime, jsonResponse, privateKey)

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "response-time": formattedDateTime,
        "client-id": clientId,
        "signature": "algorithm=RSA256,keyVersion=1,signature=" + signature
    }

    # forward response as JSON
    return Response(jsonResponse, 200, headers)
    
@app.route('/query', methods=['POST'])
def query():
    # Get the JSON data from the request
    data = request.get_json()
    paymentRequestId = data.get("paymentRequestId", "")
    
    #get value from env
    load_dotenv()

    #get value from env
    clientId = os.getenv("CLIENTID")
    privateKey = os.getenv("RSAENCRYPTKEY")

    #redis
    r = redis.Redis.from_url(os.environ.get('REDIS_URL'),decode_responses=True)

    jsonDict = {}

    #check if paymentRequestId in redis (order exist), jsonDict arrangemenet
    if r.exists(paymentRequestId):
        print("exist")
        saved = r.get(paymentRequestId)
        savedSplited = saved.split('|')
        paymentId = savedSplited[0]
        paymentTime = savedSplited[1]
        paymentAmountValue = savedSplited[2]
        paymentAmountCurrency = savedSplited[3]
        payToAmountValue = savedSplited[4]
        payToAmountCurrency = savedSplited[5]

        jsonDict["result"] = {
            "resultCode": "SUCCESS",
            "resultStatus": "S",
            "resultMessage": "success"
        }

        jsonDict["paymentResult"] = {
            "resultCode": "SUCCESS",
            "resultStatus": "S",
            "resultMessage": "success"
        }

        jsonDict["paymentId"] = paymentId
        jsonDict["paymentTime"] = paymentTime

        if paymentAmountValue is not None or paymentAmountValue != "":
            jsonDict["paymentAmount"] = {
                "value": paymentAmountValue,
                "currency": paymentAmountCurrency
            }

        if payToAmountValue is not None or payToAmountValue != "":
            jsonDict["payToAmount"] = {
                "value": payToAmountValue,
                "currency": payToAmountCurrency
            }

        jsonDict["customerId"] = "1234567890123456"
    else: 
        jsonDict["result"] = {
            "resultCode": "FAIL",
            "resultStatus": "ORDER_NOT_EXIST",
            "resultMessage": "order not exist"
        }

    formattedDateTime = datetime.now(ZoneInfo("Asia/Kuala_Lumpur")).strftime("%Y%m%d%H%M%S%z")
    
    jsonResponse = json.dumps(jsonDict)

    #signature
    signature = sign("POST", "/query", clientId, formattedDateTime, jsonResponse, privateKey)

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "response-time": formattedDateTime,
        "client-id": clientId,
        "signature": "algorithm=RSA256,keyVersion=1,signature=" + signature
    }

    # forward response as JSON
    return Response(jsonResponse, 200, headers)


if __name__ == "__main__":
    app.run(port=7777, debug=True)