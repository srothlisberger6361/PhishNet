**PhishNet: Cybersquatting Hunting**

Cybersquatting is when someone registers a domain name that is similar to a legitimate domain name, by capitalizing on common typographical errors made by web users when searching a domain in a browser (like facebool.com) or by textually looking very similar to the original domain (like 'l' for 'i' in internatlonal.org), especially if email phishing is the goal. This project helps detect, analyze, and keep track of emerging domain permutations that may be targeting your organization. 

![image](https://github.com/srothlisberger6361/PhishNet/assets/39919375/e358d10d-c681-4622-9fd9-d6431b478e1b)
## APIs/Endpoints Used
* dnstwister.report (for fetching domain permutations/typosquatted domains)
* urlscan.io (for fetching a DOM screenshot of the website for reference) **Need Free API Key**
* domainr (for fetching registration status of the domain permutations) **Need Free API Key**
* virustotal (for fetching IP and domain reputation status') **Need Free API Key**
* ipinfo.io (for fetching the Country the website is hosted in)
* whois55 (for fetching when the domain permutation was updated/created) **Need Free API Key**
## Requirements
`pip install -r requirements.txt`

## Running It
With the previous file in the same directory (if available):

`python3 phishnet.py`
