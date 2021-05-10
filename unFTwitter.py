# coding=utf-8
# بسم الله
import hmac
import hashlib
import requests
import random
import json
import urllib
import math

def generate_random_key(length):
    xx = "0123456789ABCDEF"
    return ''.join(random.choice(xx) for _ in range(length))

def randomUUID():
    UUID8 = generate_random_key(8)
    UUID4 = generate_random_key(4)
    UUID4_2 = generate_random_key(3)
    UUID4_3 = generate_random_key(4)
    UUID12 = generate_random_key(12)
    randomUUID = "{}-{}-4{}-{}-{}".format(UUID8,UUID4,UUID4_2,UUID4_3,UUID12)
    return randomUUID

def GuestToken():
    url = 'https://api.twitter.com/1.1/guest/activate.json'
    headers = {'Host': 'api.twitter.com',
                'X-Twitter-Client-DeviceID': randomUUID(),
                'Authorization':'Bearer {}'.format('AAAAAAAAAAAAAAAAAAAAAAj4AQAAAAAAPraK64zCZ9CSzdLesbE7LB%2Bw4uE%3DVJQREvQNCZJNiz3rHO7lOXlkVOQkzzdsgu6wWgcazdMUaGoUGm'),
                'X-Client-UUID': randomUUID()}

    get_guest_token_ = requests.post(url, headers=headers)
    json_guest_token = json.loads(get_guest_token_.content)
    guest_token=json_guest_token['guest_token']
    return guest_token
def login(Username,Password):
    url = 'https://api.twitter.com/auth/1/xauth_password.json'
    headers = {'User-Agent':'Twitter-HEXXXX/8.27.1 iOS/13.3 (Apple;hex,6;;;;;1;2017)',
               'Host': 'api.twitter.com' ,
               'X-Twitter-Client-DeviceID':randomUUID(),
               'Authorization':'Bearer {}'.format('AAAAAAAAAAAAAAAAAAAAAAj4AQAAAAAAPraK64zCZ9CSzdLesbE7LB%2Bw4uE%3DVJQREvQNCZJNiz3rHO7lOXlkVOQkzzdsgu6wWgcazdMUaGoUGm'),
               'X-Client-UUID':randomUUID(),
               'X-Guest-Token':GuestToken(),
               'Content-Type':'application/x-www-form-urlencoded'}
    data  = 'send_error_codes=1&x_auth_identifier={}&x_auth_login_verification=true&x_auth_password={}'.format(Username,Password)
    login = requests.post(url , data=data ,headers=headers)
    return login

def getFoloowers(oauth_token_secret,oauth_token):
    key = "GgDYlkSvaPxGxC4X8liwpUoqKwwr3lCADbz8A7ADU&{}".format(oauth_token_secret)
    zz = "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Ffriends%2Flist.json&count%3D200%26oauth_consumer_key%3DIQKbtAYlXLripLGPWd0HUA%26oauth_nonce%3D133333333337%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1620552406%26oauth_token%3D{}%26oauth_version%3D1.0".format(oauth_token)
    xxx1 = urllib.pathname2url(hmac.new(key, msg=zz, digestmod=hashlib.sha1).digest().encode('base64'))
    headers = {'Connection': 'close', 'X-Twitter-Client-Language': 'en',
               'Content-Type': 'application/x-www-form-urlencoded', 'Host': 'api.twitter.com',
               'Authorization': 'OAuth oauth_signature="{}", oauth_nonce="133333333337", oauth_timestamp="1620552406", oauth_consumer_key="IQKbtAYlXLripLGPWd0HUA", oauth_token="{}", oauth_version="1.0", oauth_signature_method="HMAC-SHA1"'.format(xxx1,oauth_token)}
    mylist = list()
    req1 = requests.get("https://api.twitter.com/1.1/friends/list.json?count=200",headers=headers)
    if req1.status_code == 200:
        for ss in json.loads(req1.content)['users']:
            mylist.append(ss['id'])
        for ids in mylist:
            zz1 = "POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Ffriendships%2Fdestroy.json&oauth_consumer_key%3DIQKbtAYlXLripLGPWd0HUA%26oauth_nonce%3D133333333337%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1620552406%26oauth_token%3D{}%26oauth_version%3D1.0%26user_id%3D{}".format(oauth_token,ids)
            xx22 = urllib.pathname2url(hmac.new(key, msg=zz1, digestmod=hashlib.sha1).digest().encode('base64'))
            headers = {'Connection': 'close', 'X-Twitter-Client-Language': 'en',
                       'Content-Type': 'application/x-www-form-urlencoded', 'Host': 'api.twitter.com',
                       'Authorization': 'OAuth oauth_signature="{}", oauth_nonce="133333333337", oauth_timestamp="1620552406", oauth_consumer_key="IQKbtAYlXLripLGPWd0HUA", oauth_token="{}", oauth_version="1.0", oauth_signature_method="HMAC-SHA1"'.format(
                           xx22, oauth_token)}
            req22 = requests.post(url="https://api.twitter.com/1.1/friendships/destroy.json",
                                data="user_id={}".format(ids), headers=headers)
            if req22.status_code == 200:
                print("userid has been unfollowed:" ,ids)
            else:
                print("error")
    else:
        print("somthing wrong ")

username = raw_input("username: ")
password = raw_input("password: ")
retry = int(raw_input("how many users did u followed but number: "))
xxx = login(username,password)
ss = math.ceil(retry / float(200))
if xxx.status_code == 401:
     print(xxx.content)
     print("are u sure about username and password")
elif xxx.status_code == 200:
    jsondata = json.loads(xxx.content)
    oauth_token = jsondata['oauth_token']
    oauth_token_secret = jsondata['oauth_token_secret']
    for cc in range(int(10*ss)):
        getFoloowers(oauth_token_secret,oauth_token)
