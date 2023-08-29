[comment]: # "Auto-generated SOAR connector documentation"
# HYAS Insight

Publisher: HYAS  
Connector Version: 1\.2\.0  
Product Vendor: HYAS  
Product Name: HYAS Insight  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.4  

This app implements investigative actions that return HYAS Insight Records for the given Indicators

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) HYAS, 2022-2023"
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""



### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a HYAS Insight asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apikey** |  required  | password | API KEY

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[lookup commandcontrol domain](#action-lookup-commandcontrol-domain) - Perform this action to get the C2 Domain Lookup Data for HYAS Insight  
[lookup commandcontrol email](#action-lookup-commandcontrol-email) - Perform this action to get the C2 Email address Lookup Data for HYAS Insight  
[lookup commandcontrol ip](#action-lookup-commandcontrol-ip) - Perform this action to get the C2 IP Lookup Data for HYAS Insight  
[lookup commandcontrol hash](#action-lookup-commandcontrol-hash) - Perform this action to get the C2 Hash Lookup Data for HYAS Insight  
[lookup whois domain](#action-lookup-whois-domain) - Perform this action to get the Whois Domain Lookup Data for HYAS Insight  
[lookup whois email](#action-lookup-whois-email) - Perform this action to get the Whois Email address Lookup Data for HYAS Insight  
[lookup whois phone](#action-lookup-whois-phone) - Perform this action to get the Whois Phone number Lookup Data for HYAS Insight  
[lookup dynamicdns email](#action-lookup-dynamicdns-email) - Perform this action to get the Dynamicdns Email address Lookup Data for HYAS Insight  
[lookup dynamicdns ip](#action-lookup-dynamicdns-ip) - Perform this action to get the Dynamicdns IP address Lookup Data for HYAS Insight  
[lookup dynamicdns domain](#action-lookup-dynamicdns-domain) - Perform this action to get the Dynamicdns Domain Lookup Data for HYAS Insight  
[lookup sinkhole ip](#action-lookup-sinkhole-ip) - Perform this action to get the Sinkhole IP address Lookup Data for HYAS Insight  
[lookup passivehash ip](#action-lookup-passivehash-ip) - Perform this action to get the Passivehash IP address Lookup Data for HYAS Insight  
[lookup passivehash domain](#action-lookup-passivehash-domain) - Perform this action to get the Passivehash Domain Lookup Data for HYAS Insight  
[lookup ssl certificate ip](#action-lookup-ssl-certificate-ip) - Perform this action to get the SSL Certificate Lookup Data for HYAS Insight  
[lookup passivedns domain](#action-lookup-passivedns-domain) - Perform this action to get the Passivedns Domain Lookup Data for HYAS Insight  
[lookup current whois domain](#action-lookup-current-whois-domain) - Perform this action to get the Whois current Domain Lookup Data for HYAS Insight  
[lookup passivedns ip](#action-lookup-passivedns-ip) - Perform this action to get the Passivedns IP address Lookup Data for HYAS Insight  
[lookup malware information hash](#action-lookup-malware-information-hash) - Perform this action to get the Malware Information Lookup Data for HYAS Insight  
[lookup malware record hash](#action-lookup-malware-record-hash) - Perform this action to get the Malware Record hash Lookup Data for HYAS Insight  
[lookup malware record ip](#action-lookup-malware-record-ip) - Perform this action to get the Malware Record IP address Lookup Data for HYAS Insight  
[lookup malware record domain](#action-lookup-malware-record-domain) - Perform this action to get the Malware Record Domain Lookup Data for HYAS Insight  
[lookup os indicator hash](#action-lookup-os-indicator-hash) - Perform this action to get the OS Indicator Lookup Data for HYAS Insight  
[lookup ssl certificate hash](#action-lookup-ssl-certificate-hash) - Perform this action to get the SSL Certificate hash Lookup Data for HYAS Insight  
[lookup ssl certificate domain](#action-lookup-ssl-certificate-domain) - Perform this action to get the SSL Certificate Domain Lookup Data for HYAS Insight  
[lookup devicegeo ip](#action-lookup-devicegeo-ip) - Perform this action to get the Mobile Geolocation Information IP address Lookup Data for HYAS Insight  
[lookup os indicator domain](#action-lookup-os-indicator-domain) - Perform this action to get the OS Indicator Domain Lookup Data for HYAS Insight  
[lookup os indicator ip](#action-lookup-os-indicator-ip) - Perform this action to get the OS Indicator Lookup Data for IP address HYAS Insight  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup commandcontrol domain'
Perform this action to get the C2 Domain Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get Lookup Data for HYAS Insight | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup commandcontrol email'
Perform this action to get the C2 Email address Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email address to get Lookup Data for HYAS Insight | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup commandcontrol ip'
Perform this action to get the C2 IP Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to get Lookup Data for HYAS Insight | string |  `ip`  `ipv4`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv4`  `ipv6` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup commandcontrol hash'
Perform this action to get the C2 Hash Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to get Lookup Data for HYAS Insight | string |  `sha256`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `sha256`  `hash` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup whois domain'
Perform this action to get the Whois Domain Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get Lookup Data for HYAS Insight | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup whois email'
Perform this action to get the Whois Email address Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email address to get Lookup Data for HYAS Insight | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup whois phone'
Perform this action to get the Whois Phone number Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**phone** |  required  | Phone number to get Lookup Data for HYAS Insight | string |  `phone`  `phone number` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.phone | string |  `number` 
action\_result\.parameter\.phone | string |  `phone`  `phone number` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup dynamicdns email'
Perform this action to get the Dynamicdns Email address Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email address to get Lookup Data for HYAS Insight | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup dynamicdns ip'
Perform this action to get the Dynamicdns IP address Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to get Lookup Data for HYAS Insight | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup dynamicdns domain'
Perform this action to get the Dynamicdns Domain Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get Lookup Data for HYAS Insight | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup sinkhole ip'
Perform this action to get the Sinkhole IP address Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ipv4** |  required  | IP address to get Lookup Data for HYAS Insight | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ipv4 | string |  `ip` 
action\_result\.parameter\.ipv4 | string |  `ip` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup passivehash ip'
Perform this action to get the Passivehash IP address Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ipv4** |  required  | IP address to get Lookup Data for HYAS Insight | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ipv4 | string |  `ip` 
action\_result\.parameter\.ipv4 | string |  `ip` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup passivehash domain'
Perform this action to get the Passivehash Domain Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get Lookup Data for HYAS Insight | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ssl certificate ip'
Perform this action to get the SSL Certificate Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to get Lookup Data for HYAS Insight | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup passivedns domain'
Perform this action to get the Passivedns Domain Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get Lookup Data for HYAS Insight | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup current whois domain'
Perform this action to get the Whois current Domain Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get Lookup Data for HYAS Insight | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup passivedns ip'
Perform this action to get the Passivedns IP address Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ipv4** |  required  | IP address to get Lookup Data for HYAS Insight | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ipv4 | string |  `ip` 
action\_result\.parameter\.ipv4 | string |  `ip`  `ipv6` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup malware information hash'
Perform this action to get the Malware Information Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to get lookup data for HYAS Insight | string |  `md5`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `md5` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup malware record hash'
Perform this action to get the Malware Record hash Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to get the lookup data for HYAS Insight | string |  `hash`  `md5`  `sha256`  `sha1` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha256`  `sha1` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup malware record ip'
Perform this action to get the Malware Record IP address Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ipv4** |  required  | IP address to get the lookup data for HYAS Insight | string |  `ip`  `ipv4` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ipv4 | string |  `ip`  `ipv4` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup malware record domain'
Perform this action to get the Malware Record Domain Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get the lookup data for HYAS Insight | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup os indicator hash'
Perform this action to get the OS Indicator Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to get lookup data for HYAS Insight | string |  `hash`  `md5`  `sha1`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha1`  `sha256` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ssl certificate hash'
Perform this action to get the SSL Certificate hash Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to get lookup data for HYAS Insight | string |  `md5`  `hash`  `sha1`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `ip` 
action\_result\.parameter\.hash | string |  `md5`  `hash`  `sha1`  `sha256` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ssl certificate domain'
Perform this action to get the SSL Certificate Domain Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get Lookup Data for HYAS Insight | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup devicegeo ip'
Perform this action to get the Mobile Geolocation Information IP address Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to get the lookup data for HYAS Insight | string |  `ip`  `ipv4`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv4`  `ipv6` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup os indicator domain'
Perform this action to get the OS Indicator Domain Lookup Data for HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get lookup data for HYAS Insight | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup os indicator ip'
Perform this action to get the OS Indicator Lookup Data for IP address HYAS Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to get the lookup data for HYAS Insight | string |  `ip`  `ipv4`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`  `ipv4`  `ipv6` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 