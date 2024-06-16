# import csv
# from datetime import date, datetime
import ipaddress
import re
from bs4 import BeautifulSoup
import favicon
import requests
import tldextract
# import whois
from googlesearch import search
# 1 -> phishing
# 0 -> not phishing
def extractFeatures(url):
    features = []
    # 1 IP in URL
    try:
        # URL contains IP
        ip = ipaddress.ip_address(url)
        features.append(1)
    except:
        features.append(0)
    # 2 Long URL
    if len(url)>54:
        features.append(1)
    else:
        features.append(0)
    # 3 URL Shortening Service
    shortening_service = [r'bit\.ly',
        r'tinyurl\.com',
        r'rebrandly\.com',
        r'snip\.ly',
        r'is\.gd',
        r't\.co',
        r'tiny\.cc',
        r'ow\.ly',
        r'shorte\.st',
        r'adf\.ly',
        r'bit\.do',
        r'b\.link',
        r'shortcm\.xyz',
        r'short\.cm',
        r't2mio\.com',
        r'cutt\.ly',
        r'buff\.ly',
        r'polr\.me',
        r'soo\.gd',
        r'y\.gy',
        r'shorturl\.at',
        r't\.ly',
        r'capsulink\.com',
        r'linklyhq\.com',
        r'vurl\.com',
        r'rplg\.co',
        r'lnnkin\.co',
        r'lnnk\.in',
        r'tny\.im',
        r'dz4link\.com',
        r'itron\.com'
    ]
    found = False
    for pattern in shortening_service:
        if re.search(pattern,url):
            features.append(1)
            found = True
            break
    if not found:
        features.append(0)
    # 4 @ symbol in URL
    if url.find('@') < 0:
        features.append(0) # no @
    else:
        features.append(1)
    # 5 // Redirect
    if url.rfind('//') > 7:
        features.append(1) # // Position HTTPS -> 6
    else:
        features.append(0)
    # 6 Prefix Suffix in Domain
    tldextract_result = tldextract.extract(url)
    if tldextract_result.domain.count('-') > 0:
        features.append(1)
    else:
        features.append(0)
    # 7 Sub Domains
    if tldextract_result.subdomain.count('.') > 0:
        features.append(1) # 2 or more subdomains
    else:
        features.append(0)
    # 8 Using HTTPS
    if re.findall(r'^https:\/\/',url):
        features.append(0)
    else:
        features.append(1)
    # 9 Domain Registration Length
    # try:
    #     w = whois.whois((tldextract_result.domain+tldextract_result.suffix))
    #     creation = w.creation_date
    #     expiration = w.expiration_date
    #     diff = abs(expiration-creation).days
    #     # print(creation)
    #     # print(expiration)
    #     print(w)
    #     if diff <= 365:
    #         features.append(1)
    #     else:
    #         features.append(0)
    # except:
    # features.append(1)

    # whois module not stable, drop column Domain Registration Length, Abnormal URL, Age of Domain, DNS Record

    # 10 Favicon
    try:
        icons = favicon.get(url)
        found = 0
        for icon in icons:
            tldextract_favicon = tldextract.extract(icon.url)
            # print(tldextract_favicon.domain)
            if tldextract_result.domain.count('.') != tldextract_favicon.domain.count('.'):
                features.append(1)
                found = 1
                break
            if tldextract_result.domain != tldextract_favicon.domain:
                features.append(1)
                found = 1
                break
        if found == 0:
            features.append(0)
    except:
        icons = -1
        features.append(1)
    
    # 11 Non Standard Port
    if url.count(':') > 1:
        port = url.split(':')
        if port[-1] == '80' or port[-1] == '443':
            features.append(0)
        else:
            features.append(1)
    else:
        features.append(0)

    # 12 HTTPS in URL (fake https)
    https = url.split(':')
    if re.findall('https',https[1], re.IGNORECASE):
        features.append(1)
    else:
        features.append(0)
        
    # 13 Request URL
    tags = ['iframe',
            'object',
            'img',
            'svg',
            'picture',
            'audio',
            'video',
            'embed',
            'track']
    found = 0
    external = 0
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        soup = BeautifulSoup(response.text,'html.parser')
    except:
        soup = -1
        print('No Response')
    if soup == -1:
        features.append(1)
    else:
        for tag in tags:
            for link in soup.find_all(tag, src=True):
                # print(link.get('src'))
                src = tldextract.extract(link.get('src'))
                found+=1
                if src.domain != tldextract_result.domain and re.search('^http', link.get('src')):
                    external+=1
        # print(found)
        # print(external)
        if external == 0:
            features.append(0)
        else:
            percent = external/float(found)
            if percent > 0.22:
                features.append(1)
            else:
                features.append(0)
    
    # 14 URL of Anchor
    found = 0
    external = 0
    if soup == -1:
        features.append(1)
    else:
        for a in soup.find_all('a', href=True):
            # starts with # or javascript
            src = tldextract.extract(a.get('href'))
            found+=1
            if re.search('^#', a.get('href')) or re.search('^javascript', a.get('href'), re.IGNORECASE) or (src.domain != tldextract_result.domain and re.search('^http', a.get('href'))):
                external+=1
        if external == 0:
            features.append(0)
        else:
            percent = external/float(found)
            if percent > 0.31:
                features.append(1)
            else:
                features.append(0)
    
    # 15 Links in <meta> <script> <link>
    found = 0
    external = 0
    if soup == -1:
        features.append(1)
    else:
        for link in soup.find_all('link', href=True):
            # print(link.get('src'))
            src = tldextract.extract(link.get('href'))
            found+=1
            if src.domain != tldextract_result.domain and re.search('^http', link.get('href')):
                external+=1
                # print(link.get('href'))
        for script in soup.find_all('script', src=True):
            # print(link.get('src'))
            src = tldextract.extract(script.get('src'))
            found+=1
            if src.domain != tldextract_result.domain and re.search('^http', script.get('src')):
                external+=1
                # print(script.get('src'))
        for meta in soup.find_all('meta', content=True):
            urls = re.findall(r'(https?:\/\/[^\s]+)', meta.get('content'))
            for link in urls:
                found+=1
                src = tldextract.extract(link)
                if src.domain != tldextract_result.domain:
                    external+=1  
        # print(found)
        # print(external)
        if external == 0:
            features.append(0)
        else:
            percent = external/float(found)
            if percent > 0.17:
                features.append(1)
            else:
                features.append(0)
        
    # 16 Server Form Handler
    if soup == -1:
        features.append(1)
    else:
        f = True
        for sfh in soup.find_all('form', action=True):
            # print(sfh.get('action'))
            # break
            if sfh.get('action') == '' or sfh.get('action') == 'about:blank' or (tldextract_result.domain not in sfh.get('action') and re.search('^http', sfh.get('action'))):
                features.append(1)
                f = False
                break
            # else:
            #     print(sfh.get('action'))
        if f:
            features.append(0)
            # print(0)

    # 17 Submitting Information to Email
    if soup == -1:
        features.append(1)
    else:
        if 'mail()' in response.text or 'mailto:' in response.text:
            features.append(1)
        else:
            features.append(0)
            
    # 18 Abnormal URL (Host name not in URL)
    # print(w.domain)
    # print(tldextract_result.domain)
    # if w == -1:
    # features.append(1)
    # else:
    #     if tldextract_result.domain not in w.domain:
    #         features.append(1)
    #     else:
    #         features.append(0)

    # 19 Website Forwarding
    if soup == -1:
        features.append(1)
    else:
        if len(response.history) < 2:
            features.append(0)
        else:
            features.append(1)
    
    # 20 Status Bar Customization
    if soup == -1:
        features.append(1)
    else:
        if re.findall(r'<.+onmouseover=[\"\']window\.status.+>', response.text):
            features.append(1)
        else:
            features.append(0)

    # 21 Disabled Right Click
    if soup == -1:
        features.append(1)
    else:
        if re.findall(r'event.button *==? *2', response.text): #or re.findall(r'',response.text)
            features.append(1)
        else:
            features.append(0)

    # 22 Text Field in Popup Window
    if soup == -1:
        features.append(1)
    else:
        if re.findall(r'prompt\(.+\)', response.text):
            features.append(1)
        else:
            features.append(0)

    # 23 Iframe Redirection
    if soup == -1:
        features.append(1)
    else:
        if re.findall(r'\<iframe(.|\n)*frameborder *= *(\'|\")0', response.text):
            features.append(1)
        else:
            features.append(0)

    # 24 Age of Domain
    # if w == -1:
    # features.append(1)
    # else:
    #     diff = abs(datetime.now() - creation).days
    #     if diff > 180:
    #         features.append(0)
    #     else:
    #         features.append(1)

    # 25 DNS Record
    # if w == -1:
    # features.append(1)
    # else:
    #     features.append(0)

    # 26 Website Traffic (Alexa rank database discontinued in 2022)
    
    # 27 Page Rank (Dari DomCop Open PageRank, Lowest page rank disini 3.11/10)
    try:
        params = {'sSearch':tldextract_result.domain}
        page_rank = requests.get('https://www.domcop.com/service/getTopDomains.php', params)
        f = 0
        for lines in page_rank:
            if b'iTotalRecords' in lines: # response in binary format
                lines = lines.decode('ascii')
                iTotalRecords = re.findall(r'\b\d+\b',lines)
                if int(iTotalRecords[1]) > 0:
                    features.append(0)
                    f = 1
                else:
                    features.append(1)
                    f = 1
                break
        if f == 0:
            features.append(1)
    except:
        features.append(1)
    # features.append(0)-
    # 28 Google Index
    idx = search(url)
    if idx:
        features.append(0)
    else:
        features.append(1)
    # features.append(0)
    # 29 Number of links pointing to page
    if soup == -1:
        features.append(1)
    else:
        links = len(re.findall(r'<a href=', response.text))
        if links > 2:
            features.append(0)
        else:
            features.append(1)
    # 30 Statistical-Reports Based Feature
    # Stop badware dns error, phishtank last update may 2017
            # Total features = 24

    return features