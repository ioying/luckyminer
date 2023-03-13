#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

# pip install requests
# pip install requests-toolbelt

import gc      # garbage collector
import json
#import logging
import math
import os
#import psutil  # cpu memory info
import random
import re
import requests
import sys
import threading
import time
import traceback
import luckyMiner.config as C


#
# Encode a sequence of bytes as Base58
# and return the corresponding sequence of characters
#
# see base58.cpp 
#
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def base58Encode(s):
    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    #assert(isinstance(s, bytes))
    #
    # Count the number of leading zeros
    #
    zeros = 0
    while (zeros < len(s)) and (s[zeros] == 0):
        zeros = zeros + 1
    #
    # Convert to integer first, using big endian encoding
    #
    value = int.from_bytes(s, 'big')
    #
    # Now convert the integer to base 58
    #
    result= ""
    while value:
        value, digit = divmod(value, 58)
        result = BASE58_ALPHABET[digit] + result
    #
    # Append leading 1's again
    #
    for _ in range(zeros):
        result = '1' + result
    return result

#
# Decode a Base58 encoded string and return a
# sequence of bytes
#
def base58Decode(s):
    #
    # Strip off leading 1's as these represent leading
    # zeros in the original
    #
    zeros = 0
    while (zeros < len(s)) and (s[zeros] == '1'):
        zeros = zeros + 1
    s = s[zeros:]
    #
    # We first turn the string into an integer
    #
    value, power = 0, 1
    for _ in reversed(s):
        value += power * BASE58_ALPHABET.index(_)
        power = power * 58
    #
    # Now convert this integer into a sequence of bytes
    # 
    result = value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')
    #
    # and append the leading zeros again
    #
    for _ in range(zeros):
        result = (0).to_bytes(1, 'big') + result
    return result


def saveBlock(block_template, transactions=0, once = 0):
    # transactions: keep transaction data or not
    PATH = C.LOG_PATH
    fileName = PATH+str(block_template['height'])+'.log'
    if transactions == 0:
        block_template['transactions'] = block_template['transactions'][0]
    
    if once == 1 and os.path.exists(fileName) :
        return
    
    with open(fileName, 'a+', encoding='utf-8') as f:
        #f.write(json.dumps(block_template)+"@"+ time.asctime( time.localtime(time.time()))+'\n')
        f.write(json.dumps(block_template)+'\n')
    return                    


def mPrint(MSx='', level=3, *msg):
    PATH = C.LOG_PATH
    fileName = PATH + 'info_log_'+time.strftime("%Y-%m-%d", time.localtime())+'.log'
    print(MSx,*msg)
    #print( fileName)
    if level > 1 :
        try:
            with open(fileName, 'a+', encoding='utf-8') as f:
                print(MSx,*msg,"@"+ time.asctime( time.localtime(time.time()))+'\n',file=f)
        except:
            pass
    return    


# dict key to upper 
def upperDict(data):
    new_dict = {}
    for i, j in data.items():
        new_dict[i.upper()] = j
    return new_dict


def htmlspecialchars(dataStr):
    return dataStr.replace('<', '_').replace('>','_').replace('(', '（').\
               replace(')', '）').replace('None', '0').replace('null', '0')

def isoToTimestamp(isostr):
    t=time.strptime(isostr,'%Y-%m-%dT%H:%M:%S.%fZ')
    return time.mktime(t)

def req(URL, method='GET', header={}, params={}, timeOut=9):
    if method == 'GET':
        try:
            response = requests.get(URL, headers=header, timeout= timeOut )
        except requests.exceptions.TooManyRedirects as e:
            res = {'code':'-4','msg':'TooManyRedirects'}
        except requests.exceptions.ConnectTimeout as e:
            res = {'code':'-3','msg':'ConnectTimeout'}
        except requests.exceptions.Timeout as e:
            res = {'code':'-2','msg':'timeout'}
        except: 
            res = {'code':'-1','msg':'Unknow ConnectionError'}
        else:    
            if response.status_code == 200:      
                res = {'code':'0','res':response.json()}
            else:
                res = {'code':'-1','res':response.text[:300]} 
        #response.close()
        return res     
    if method == 'POST':
        try:
            #print(params)
            response = requests.post(URL, params,headers=header, timeout=timeOut)
        except Exception as e:
            return {'code': '-1','res': 'Unknow ConnectionError'}
        else:    
            if response.status_code == 200:      
                #php debug=true will cause json format error
                #print(response,response.text)
                res = {'code': '0','res': response.json()}
            else:
                res = {'code': '-1','res': response.text[:300]} 
        #response.close()
        return res
        
def restart_program(delay=5):
    mPrint('s_t_a_r_t',1,("restart",'s_t_a_r_t',*sys.argv))
    for i in range(delay):
        print('restart after', delay - i, 'sec  ')
        time.sleep(1)
    python = sys.executable 
    os.execl(python, python, *sys.argv)  
    return
    
def get_size(obj, seen=None):
    #https://goshippo.com/blog/measure-real-size-any-python-object/
    """Recursively finds size of objects"""
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    # Important mark as seen *before* entering recursion to gracefully handle
    # self-referential objects
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    return size    

def delLabel(html):
    pattern = re.compile(r'<[^>]+>',re.S)
    return pattern.sub('', str(html))
    
