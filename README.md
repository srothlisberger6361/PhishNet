## PhishNet: Cybersquatting Hunting

Cybersquatting is when someone registers a domain name that is similar to a legitimate domain name, by capitalizing on common typographical errors made by web users when searching a domain in a browser (like facebool.com) or by textually looking very similar to the original domain (like 'l' for 'i' in internatlonal.org), especially if email phishing is the goal. This project helps detect, analyze, and keep track of emerging domain permutations that may be targeting your organization. 

<table>
  <tr>
    <td><img src="https://github.com/srothlisberger6361/PhishNet/assets/39919375/e358d10d-c681-4622-9fd9-d6431b478e1b" alt="image" width="200"/></td>
    <td>
      <h2>APIs/Endpoints Used</h2>
      <ul>
        <li>dnstwister.report (for fetching domain permutations/typosquatted domains)</li>
        <li>urlscan.io (for fetching a DOM screenshot of the website for reference) <strong>Need Free API Key</strong></li>
        <li>domainr (for fetching registration status of the domain permutations) <strong>Need Free API Key</strong></li>
        <li>virustotal (for fetching IP and domain reputation status') <strong>Need Free API Key</strong></li>
        <li>ipinfo.io (for fetching the Country the website is hosted in)</li>
        <li>whois55 (for fetching when the domain permutation was updated/created) <strong>Need Free API Key</strong></li>
      </ul>
    </td>
  </tr>
</table>

## Requirements
`pip install -r requirements.txt`

## Running It
With the previous file in the same directory (if available):

`python3 phishnet.py`
