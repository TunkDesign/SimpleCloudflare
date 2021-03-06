# Simple Cloudflare
Simple Cloudflare is a simple and easy to use python script for managing Cloudflare enabled domains. Simple Cloudflare is easy to implement into any bash script for easy to access JSON data.

## Usage
```sh
$ dns.py EMAIL APIKEY ACTION
```

* **EMAIL** = Your Cloudflare account email.
* **APIKEY** = Your Cloudflare api key. Can be found at the bottom of this [page](https://www.cloudflare.com/my-account)
* **ACTION** = The action you want to perform *(Check out the list below)*

## Actions
To see a list of actions you can use, issue the following:
```sh
$ dns.py actions
```
___
####zones
```sh
$ dns.py EMAIL APIKEY zones
```
The **zones** action will show you a list of all domains on the selected Cloudflare account, along with other data.
___
####dns.domain
```sh
$ dns.py EMAIL APIKEY dns.example.com
```
The **dns.domain** action will show you a list of all the DNS records that the selected domain has.
___
####dns.domain readable
```sh
$ dns.py EMAIL APIKEY dns.example.com readable
```
The **dns.domain readable** action is the same as above but outputs readable data instead of a JSON mess.
___
####dns.create.domain.type "content" "name"
```sh
$ dns.py EMAIL APIKEY dns.create.example.com.A 127.0.0.1 localhost
```
The **dns.create.domain.type** action will create a new DNS record on the selected domain.

#####Examples
- **Create an A record** - *Point/Spoof a subdomain to an IP address* - ***This points localhost.example.com to 127.0.0.1***
```sh
$ dns.py EMAIL APIKEY dns.create.example.com.A 127.0.0.1 localhost
```
- **Create a CNAME record** - *Create a subdomain as a domain alias* - ***This makes search.example.com show the content on google.com***
```sh
$ dns.py EMAIL APIKEY dns.create.example.com.CNAME google.com search
```
- **Create an MX record** - *Add mail exhanger servers to handle email messages* - ***This makes the server at email.google.com recieve all emails sent to example.com with a priority of 10***
```sh
$ dns.py EMAIL APIKEY dns.create.example.com.MX.10 email.google.com example.com
```
- **Create a TXT record** - *Add plaintext data to your DNS whois. Human readable data.* - ***This does something with plaintext data***
```sh
$ dns.py EMAIL APIKEY dns.create.example.com.TXT "\"v=spf1 ~all\"" example.com
```
___
####dns.delete.domain.id
```sh
$ dns.py EMAIL APIKEY dns.delete.example.com.1845487
```
The **dns.delete.domain.id** action will delete a DNS record by id. Id can be found by running **dns.domain**
___
####whitelist "ip"
```sh
$ dns.py EMAIL APIKEY whitelist 127.0.0.1
```
The **whitelist** action will whitelist the selected IP. (Trusted IP)
___
####blacklist "ip"
```sh
$ dns.py EMAIL APIKEY blacklist 127.0.0.1
```
The **blacklist** action will blacklist/block/ban the selected IP.
___
####lookup "ip" *(Broken)*
```sh
$ dns.py EMAIL APIKEY lookup 127.0.0.1
```
The **lookup** action will check the current threat level of the selected IP.
___
