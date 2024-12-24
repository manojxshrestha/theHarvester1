![theHarvester](https://github.com/laramies/theHarvester/blob/master/theHarvester-logo.webp)

![TheHarvester CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Python%20CI/badge.svg) ![TheHarvester Docker Image CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Docker%20Image%20CI/badge.svg)
[![Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/img/badges/Rawsec-inventoried-FF5050_flat_without_logo.svg)](https://inventory.raw.pm/)

What is this?
-------------
theHarvester is a simple to use, yet powerful tool designed to be used during the reconnaissance stage of a red<br>
team assessment or penetration test. It performs open source intelligence (OSINT) gathering to help determine<br>
a domain's external threat landscape. The tool gathers names, emails, IPs, subdomains, and URLs by using<br>
multiple public resources that include:<br>

Passive modules:
----------------
* anubis: Anubis-DB - https://github.com/jonluca/anubis

* bevigil: CloudSEK BeVigil scans mobile application for OSINT assets (Requires an API key, see below.) - https://bevigil.com/osint-api

* baidu: Baidu search engine - www.baidu.com

* binaryedge: List of known subdomains (Requires an API key, see below.) - https://www.binaryedge.io

* bing: Microsoft search engine - https://www.bing.com

* bingapi: Microsoft search engine, through the API (Requires an API key, see below.)

* brave: Brave search engine - https://search.brave.com/

* bufferoverun: (Requires an API key, see below.) https://tls.bufferover.run

* censys: [Censys search engine](https://search.censys.io/) will use certificates searches to enumerate subdomains and gather emails<br>
  (Requires an API key, see below.) https://censys.io

* certspotter: Cert Spotter monitors Certificate Transparency logs - https://sslmate.com/certspotter/

* criminalip: Specialized Cyber Threat Intelligence (CTI) search engine (Requires an API key, see below.) - https://www.criminalip.io

* crtsh: Comodo Certificate search - https://crt.sh

* dnsdumpster: DNSdumpster search engine - https://dnsdumpster.com

* duckduckgo: DuckDuckGo search engine - https://duckduckgo.com

* fullhunt: Next-generation attack surface security platform (Requires an API key, see below.) - https://fullhunt.io

* github-code: GitHub code search engine (Requires a GitHub Personal Access Token, see below.) - www.github.com

* hackertarget: Online vulnerability scanners and network intelligence to help organizations - https://hackertarget.com

* hunter: Hunter search engine (Requires an API key, see below.) - https://hunter.io

* hunterhow: Internet search engines for security researchers (Requires an API key, see below.) - https://hunter.how

* intelx: Intelx search engine (Requires an API key, see below.) - http://intelx.io

* netlas: A Shodan or Censys competitor (Requires an API key, see below.) - https://app.netlas.io

* onyphe: Cyber defense search engine (Requires an API key, see below.) - https://www.onyphe.io/

* otx: AlienVault open threat exchange - https://otx.alienvault.com

* pentestTools: Cloud-based toolkit for offensive security testing, focused on web applications and network penetration<br>
  testing (Requires an API key, see below.) - https://pentest-tools.com/

* projecDiscovery: We actively collect and maintain internet-wide assets data, to enhance research and analyse changes around<br>
  DNS for better insights (Requires an API key, see below.) - https://chaos.projectdiscovery.io

* rapiddns: DNS query tool which make querying subdomains or sites of a same IP easy! https://rapiddns.io

* rocketreach: Access real-time verified personal/professional emails, phone numbers, and social media links (Requires an API key,<br>
  see below.) - https://rocketreach.co

* securityTrails: Security Trails search engine, the world's largest repository of historical DNS data (Requires an API key, see<br>
  below.) - https://securitytrails.com

* -s, --shodan: Shodan search engine will search for ports and banners from discovered hosts (Requires an API key, see below.)<br>
  https://shodan.io

* sitedossier: Find available information on a site - http://www.sitedossier.com

* subdomaincenter: A subdomain finder tool used to find subdomains of a given domain - https://www.subdomain.center/

* subdomainfinderc99: A subdomain finder is a tool used to find the subdomains of a given domain - https://subdomainfinder.c99.nl

* threatminer: Data mining for threat intelligence - https://www.threatminer.org/

* tomba: Tomba search engine (Requires an API key, see below.) - https://tomba.io

* urlscan: A sandbox for the web that is a URL and website scanner - https://urlscan.io

* vhost: Bing virtual hosts search

* virustotal: Domain search (Requires an API key, see below.) - https://www.virustotal.com

* yahoo: Yahoo search engine

* zoomeye: China's version of Shodan (Requires an API key, see below.) - https://www.zoomeye.org


Active modules:
---------------
* DNS brute force: dictionary brute force enumeration
* Screenshots: Take screenshots of subdomains that were found

Modules that require an API key:
--------------------------------
Documentation to setup API keys can be found at - https://github.com/laramies/theHarvester/wiki/Installation#api-keys

* bevigil - Free upto 50 queries. Pricing can be found here: https://bevigil.com/pricing/osint
* binaryedge - $10/month
* bing
* bufferoverun - uses the free API
* censys - API keys are required and can be retrieved from your [Censys account](https://search.censys.io/account/api).
* criminalip
* fullhunt
* github
* hunter - limited to 10 on the free plan, so you will need to do -l 10 switch
* hunterhow
* intelx
* netlas - $
* onyphe -$
* pentestTools - $
* projecDiscovery - invite only for now
* rocketreach - $
* securityTrails
* shodan - $
* tomba - Free up to 50 search.
* zoomeye

Install and dependencies:
-------------------------
* Python 3.11+
* https://github.com/laramies/theHarvester/wiki/Installation


# Installation:

            $ sudo apt-get theharvester
If it doesn’t work you can try to clone it directly from git using the following commands

            $ git clone https://github.com/laramies/theHarvester.git
            $ cd theHarvester
            $ sudo pip3 install -r requirements.txt
            $ sudo python3 ./theHarvester.py
            
# Upgrading:
use the following command to upgrade the harvester

            $ sudo apt-get upgrade theharvester

# Usage:

       $ theHarvester [-h] -d DOMAIN [-l LIMIT] [-S START] [-g] [-p] [-s] [--screenshot SCREENSHOT] [-v] [-e DNS_SERVER [-t DNS_TLD] [-r] [-n] [-c] [-f FILENAME] [-b SOURCE]


# options:

    -h, --help            show this help message and exit
   
   
    -d DOMAIN, --domain DOMAIN [Company name or domain to search]
               
               
    -l LIMIT, --limit LIMIT [Limit the number of search results, default=500]
         
         
    -S START, --start START [Start with result number X, default=0]
    
    
    -g, --google-dork [Use Google Dorks for Google search]
   
   
    -p, --proxies [Use proxies for requests, enter proxies in proxies.yaml]
   
   
    -s, --shodan [Use Shodan to query discovered hosts]
   
   
    --screenshot SCREENSHOT [Take screenshots of resolved domains specify output directory: --screenshot output_directory]
                
                
    -v, --virtual-host [Verify host name via DNS resolution and search for virtual hosts]
                   
                   
    -e DNS_SERVER, --dns-server DNS_SERVER [DNS server to use for lookup]
                      
                      
    -t DNS_TLD, --dns-tld DNS_TLD [Perform a DNS TLD expansion discovery, default False]
                
                
    -r, --take-over [Check for takeovers]
   
   
    -n, --dns-lookup [Enable DNS server lookup, default False]
  
  
    -c, --dns-brute [Perform a DNS brute force on the domain]
    
    
    -f FILENAME, --filename FILENAME [Save the results to an XML and JSON file]
                       
                       
    -b SOURCE, --source SOURCE [anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, zoomeye
                               crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter,                                    
                               intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery,                                
                               qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, yahoo, 
                               threatminer, trello, twitter, urlscan, virustotal]
                               
     

    -h: Use SHODAN database to query discovered hosts.

# Examples
To list available options
        
        
     To search emails : $ theHarvester.py -d abc.com -b all
        
     To search emails with a limit : $ theHarvester.py -d abc.com -b all -l 200
        
     To save the result into an html file : $ theharvester -d abc.com -b all -h myresults.html
        
     To search in PGP(Pretty Good Privacy) only : $ theharvester -d abc.com -b pgp     
