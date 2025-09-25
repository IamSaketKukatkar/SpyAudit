import requests
import base64
import time
import random

# Found this from the js code
def computeAntiAbuseHeader():
    timestamp = int(time.time())
    rand_value = random.randint(10000000000, 99999999999)
    raw = f"{rand_value}-ZG9udCBiZSBldmls-{timestamp}"
    return base64.b64encode(raw.encode()).decode()

headers = {
    'accept': 'application/json',
    'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
    'accept-language': 'en-US,en;q=0.5',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'referer': 'https://www.virustotal.com/',
    'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Brave";v="138"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Linux"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'sec-gpc': '1',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
    'x-app-version': 'v1x418x0',
    'x-tool': 'vt-ui-main',
    'x-vt-anti-abuse-header': computeAntiAbuseHeader(),
}

params = {
    'limit': '20',
    'query': 'google.com',
}

try:
    response = requests.get(
        'https://www.virustotal.com/ui/search',
        params=params,
        headers=headers,
        timeout=15
    )
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    
except requests.exceptions.RequestException as e:
    print(f"Request error: {str(e)}")
except Exception as e:
    print(f"Unexpected error: {str(e)}")
