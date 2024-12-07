import base64
import string
import random
import hashlib
import sys
from Crypto.Cipher import AES

class PaytmChecksum:
    @staticmethod
    def encrypt(input_data, key):
        iv = '@@@@&&&&####$$$$'
        data = input_data.encode('utf-8')
        padded_data = PaytmChecksum._pad(data)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_data, key):
        iv = '@@@@&&&&####$$$$'
        encrypted_data = base64.b64decode(encrypted_data)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        decrypted_data = cipher.decrypt(encrypted_data)
        return PaytmChecksum._unpad(decrypted_data).decode('utf-8')

    @staticmethod
    def generateSignature(params, key):
        if type(params) != dict and type(params) != str:
            raise Exception("String or dict expected, " + str(type(params)) + " given")
        
        if type(params) == dict:
            params = PaytmChecksum._getStringByParams(params)
        
        return PaytmChecksum.encrypt(params, key)

    @staticmethod
    def verifySignature(params, key, checksum):
        if type(params) != dict and type(params) != str:
            raise Exception("String or dict expected, " + str(type(params)) + " given")

        if type(params) == dict:
            params = PaytmChecksum._getStringByParams(params)
            
        return PaytmChecksum.decrypt(checksum, key) == params

    @staticmethod
    def _pad(data):
        length = 16 - (len(data) % 16)
        data += bytes([length]) * length
        return data

    @staticmethod
    def _unpad(data):
        return data[:-data[-1]]

    @staticmethod
    def _getStringByParams(params):
        params_list = []
        for key in sorted(params.keys()):
            if str(params[key]) not in ["null", "NULL", "None", "", "false"]:
                params_list.append(str(key) + "=" + str(params[key]))
        return '|'.join(params_list)
