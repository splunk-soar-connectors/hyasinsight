[comment]: # "Auto-generated SOAR connector documentation"

# Hyas Insight

Publisher: Hyas\
Connector Version: 1.0.0\
Product Vendor: Hyas  
Product Name: Hyas Insight  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5.2.0

#### HYAS Insight is a threat investigation and attribution solution that uses exclusive data sources and non-traditional mechanisms to improve visibility and productivity for analysts, researchers, and investigators while increasing the accuracy of findings. HYAS Insight connects attack instances and campaigns to billions of indicators of compromise to deliver insights and visibility. With an easy-to-use user interface, transforms, and API access, HYAS Insight combines rich threat data into a powerful research and attribution solution. HYAS Insight is complemented by the HYAS Intelligence team that helps organisations to better understand the nature of the threats they face on a daily basis.

This app implements investigative actions that return Hyas Insight
Lookup Records for the given Indicators


[comment]: # " File: README.md"

[comment]: # "  Copyright (c) Hyas, 2022"

[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"

[comment]: # "  you may not use this file except in compliance with the License."

[comment]: # "  You may obtain a copy of the License at"

[comment]: # ""

[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"

[comment]: # ""

[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"

[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"

[comment]: # "  either express or implied. See the License for the specific language governing permissions"

[comment]: # "  and limitations under the License."

[comment]: # ""

## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Hyas Protect
server. Below are the
default ports used by the Splunk SOAR Connector.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |

### Configuration Variables

The below configuration variables are required for this Connector to operate.
These variables are specified when configuring a Hyas Protect asset in SOAR.

|  VARIABLE  | REQUIRED | TYPE | DESCRIPTION|
|------------| -------- | ---- | -----------|
| **apikey** |  required  | password | API KEY|

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset
configuration for connectivity using supplied configuration

[lookup c2 domain](#action-lookup-c2-domain) - Perform this action to get the C2
Domain Lookup Data for Hyas Insight

[lookup c2 email](#action-C2-email) -Perform this action to get the C2 Email
Lookup Data for Hyas Insight

[lookup c2 ip](#action-lookup-c2-ip) - Perform this action to get the C2 IP
Lookup Data for Hyas Insight

[lookup c2 hash](#action-lookup-c2-hash) - Perform this action to get the C2
Hash Lookup Data for Hyas Insight

[lookup whois domain](#action-lookup-whois-domain) - Perform this action to get
the Whois Domain Lookup Data for Hyas Insight

[lookup whois email](#action-lookup-whois-email) - Perform this action to get
the Whois Email Lookup Data for Hyas Insight

[lookup whois phone](#action-lookup-whois-phone) - Perform this action to get
the Whois Phone Lookup Data for Hyas Insight

[lookup dynamicdns email](#action-lookup-dynamicdns-email) - Perform this action
to get the Dynamicdns Email Lookup Data for Hyas Insight

[lookup dynamicdns ip](#action-lookup-dynamicdns-ip) - Perform this action to
get the Dynamicdns IP Lookup Data for Hyas Insight

[lookup sinkhole ip](#action-lookup-sinkhole-ip) - Perform this action to get
the Sinkhole IP Lookup Data for Hyas Insight

[lookup passivehash ip](#action-lookup-passivehash-ip) - Perform this action to
get the Passivehash IP Lookup Data for Hyas Insight

[lookup passivehash domain](#action-lookup-passivehash-domain) - Perform this
action to get the Passivehash Domain Lookup Data for Hyas Insight

[lookup ssl certificate ip](#action-lookup-ssl-certificate-ip) - Perform this
action to get the SSL Certificate Lookup Data for Hyas Insight

[lookup passivedns domain](#action-lookup-passivedns-domain) - Perform this
action to get the Passivedns Domain Lookup Data for Hyas Insight

[lookup current whois domain](#action-lookup-current-whois-domain) - Perform
this action to get the Whois current Domain Lookup Data for Hyas Insight

[lookup passivedns ip](#action-lookup-passivedns-ip) - Perform this action to
get the Passivedns IP Lookup Data for Hyas Insight

[lookup malware information hash](#action-lookup-malware-information-hash) -
Perform this action to get the Malware Information Lookup Data for Hyas Insight

[lookup malware record hash](#action-lookup-malware-record-hash) - Perform this
action to get the Malware Record hash Lookup Data for Hyas Insight

[lookup os indicator hash](#action-lookup-os-indicator-hash) - Perform this
action to get the OS Indicator Lookup Data for Hyas Insight

[lookup ssl certificate hash](#action-lookup-ssl-certificate-hash) - Perform
this action to get the SSL Certificate hash Lookup Data for Hyas Insight

[lookup Mobile Geolocation Information ipv4](#action-lookup-Mobile-Geolocation-Information-ipv4)
- Perform this action to get the Mobile Geolocation Information IPv4 Lookup Data
for Hyas Insight

[lookup Mobile Geolocation Information ipv6](#action-lookup-Mobile-Geolocation-Information-ipv6)
- Perform this action to get the Mobile Geolocation Information IPv6 Lookup Data
for Hyas Insight

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'lookup c2 domain'

Perform this action to get the C2 Domain Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER  | REQUIRED | DESCRIPTION | TYPE | CONTAINS|
|------------| -------- | ----------- | ---- | --------|
| **
domain** |  required  | Domain to get Lookup Data for Hyas Insight | string |  `"domain"`|

#### Action Output

| data_path                        | data_type | contains | example_values                                                                                                                                                      |
|----------------------------------|-----------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| action_result.parameter.domain   | string    | domain   | www.hyas.com                                                                                                                                                        |
| action_result.*.actor_ipv4       | string    | ip       | 197.210.84.34                                                                                                                                                       |
| action_result.*.c2_domain        | string    | domain   | himionsa.com                                                                                                                                                        |
| action_result.*.c2_ipv4          | string    | ip       | 80.78.22.32                                                                                                                                                         |
| action_result.*.c2_url           | string    | url      | http://www.glowtey.com/mtc/config.php?action=recoveries                                                                                                             |
| action_result.*.datetime         | string    |          | 2020/09/15 08:12:44                                                                                                                                                 |
| action_result.*.email            | string    | email    | ip@allbayrak.com                                                                                                                                                    |
| action_result.*.email_domain     | string    | domain   | allbayrak.com                                                                                                                                                       |
| action_result.*.referrer_domain  | string    | domain   | webmail.allbayrak.com                                                                                                                                               |
| action_result.*.referrer_ipv4    | string    | ip       | 46.173.218.219                                                                                                                                                      |
| action_result.*.referrer_url     | string    | url      | http://webmail.allbayrak.com/roundcube/?_task=mail&amp;_caps=pdf%3D1%2Cflash%3D0%2Ctiff%3D0%2Cwebp%3D1&amp;_uid=8&amp;_mbox=INBOX&amp;_framed=1&amp;_action=preview |
| action_result.*.sha256           | string    | sha256   | 281af32d4b70417c5027c9590f494aa9026c540a5c8af407dc3d464afe0a23ae                                                                                                    |
| action_result.parameter.domain   | string    | domain   | domain                                                                                                                                                              | 0 |
| action_result.status             | string    | status   | success Failed                                                                                                                                                      | 1 |
| action_result.message            | string    |
| summary.total_objects            | numeric   | 1        |
| summary.total_objects_successful | numeric   | 1        |

## action: 'lookup c2 email'

Perform this action to get the C2 Email Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER  | REQUIRED | DESCRIPTION | TYPE | CONTAINS|
|------------| -------- | ----------- | ---- | --------|
| **
email** |  required  | Email to get Lookup Data for Hyas Insight | string |  `"email"`|

#### Action Output

| data_path                        | data_type | contains | example_values                                                                                                                                                      |
|----------------------------------|-----------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| action_result.parameter.domain   | string    | domain   | www.hyas.com                                                                                                                                                        |
| action_result.*.actor_ipv4       | string    | ip       | 197.210.84.34                                                                                                                                                       |
| action_result.*.c2_domain        | string    | domain   | himionsa.com                                                                                                                                                        |
| action_result.*.c2_ipv4          | string    | ip       | 80.78.22.32                                                                                                                                                         |
| action_result.*.c2_url           | string    | url      | http://www.glowtey.com/mtc/config.php?action=recoveries                                                                                                             |
| action_result.*.datetime         | string    |          | 2020/09/15 08:12:44                                                                                                                                                 |
| action_result.*.email            | string    | email    | ip@allbayrak.com                                                                                                                                                    |
| action_result.*.email_domain     | string    | domain   | allbayrak.com                                                                                                                                                       |
| action_result.*.referrer_domain  | string    | domain   | webmail.allbayrak.com                                                                                                                                               |
| action_result.*.referrer_ipv4    | string    | ip       | 46.173.218.219                                                                                                                                                      |
| action_result.*.referrer_url     | string    | url      | http://webmail.allbayrak.com/roundcube/?_task=mail&amp;_caps=pdf%3D1%2Cflash%3D0%2Ctiff%3D0%2Cwebp%3D1&amp;_uid=8&amp;_mbox=INBOX&amp;_framed=1&amp;_action=preview |
| action_result.*.sha256           | string    | sha256   | 281af32d4b70417c5027c9590f494aa9026c540a5c8af407dc3d464afe0a23ae                                                                                                    |
| action_result.parameter.domain   | string    | domain   | domain                                                                                                                                                              | 0 |
| action_result.status             | string    | status   | success Failed                                                                                                                                                      | 1 |
| action_result.message            | string    |
| summary.total_objects            | numeric   | 1        |
| summary.total_objects_successful | numeric   | 1        |

## action: 'lookup c2 ip'

Perform this action to get the C2 IP Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                            | TYPE | CONTAINS |
|-----------| -------- |----------------------------------------| ---- |----------|
| **
ip**    |  required  | IP to get Lookup Data for Hyas Insight | string | `"ip"`   |

#### Action Output

| data_path                        | data_type | contains | example_values                                                                                                                                                      |
|----------------------------------|-----------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| action_result.parameter.domain   | string    | domain   | www.hyas.com                                                                                                                                                        |
| action_result.*.actor_ipv4       | string    | ip       | 197.210.84.34                                                                                                                                                       |
| action_result.*.c2_domain        | string    | domain   | himionsa.com                                                                                                                                                        |
| action_result.*.c2_ipv4          | string    | ip       | 80.78.22.32                                                                                                                                                         |
| action_result.*.c2_url           | string    | url      | http://www.glowtey.com/mtc/config.php?action=recoveries                                                                                                             |
| action_result.*.datetime         | string    |          | 2020/09/15 08:12:44                                                                                                                                                 |
| action_result.*.email            | string    | email    | ip@allbayrak.com                                                                                                                                                    |
| action_result.*.email_domain     | string    | domain   | allbayrak.com                                                                                                                                                       |
| action_result.*.referrer_domain  | string    | domain   | webmail.allbayrak.com                                                                                                                                               |
| action_result.*.referrer_ipv4    | string    | ip       | 46.173.218.219                                                                                                                                                      |
| action_result.*.referrer_url     | string    | url      | http://webmail.allbayrak.com/roundcube/?_task=mail&amp;_caps=pdf%3D1%2Cflash%3D0%2Ctiff%3D0%2Cwebp%3D1&amp;_uid=8&amp;_mbox=INBOX&amp;_framed=1&amp;_action=preview |
| action_result.*.sha256           | string    | sha256   | 281af32d4b70417c5027c9590f494aa9026c540a5c8af407dc3d464afe0a23ae                                                                                                    |
| action_result.parameter.domain   | string    | domain   | domain                                                                                                                                                              | 0 |
| action_result.status             | string    | status   | success Failed                                                                                                                                                      | 1 |
| action_result.message            | string    |
| summary.total_objects            | numeric   | 1        |
| summary.total_objects_successful | numeric   | 1        |

## action: 'lookup c2 hash'

Perform this action to get the C2 Hash Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                              | TYPE | CONTAINS                             |
|-----------| -------- |------------------------------------------| ---- |--------------------------------------|
| **
hash**  |  required  | Hash to get Lookup Data for Hyas Insight | string | `"Hash"` `"MD5"` `"SHA1"` `"SHA256"` |

#### Action Output

| data_path                        | data_type | contains | example_values                                                                                                                                                      |
|----------------------------------|-----------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| action_result.parameter.domain   | string    | domain   | www.hyas.com                                                                                                                                                        |
| action_result.*.actor_ipv4       | string    | ip       | 197.210.84.34                                                                                                                                                       |
| action_result.*.c2_domain        | string    | domain   | himionsa.com                                                                                                                                                        |
| action_result.*.c2_ipv4          | string    | ip       | 80.78.22.32                                                                                                                                                         |
| action_result.*.c2_url           | string    | url      | http://www.glowtey.com/mtc/config.php?action=recoveries                                                                                                             |
| action_result.*.datetime         | string    |          | 2020/09/15 08:12:44                                                                                                                                                 |
| action_result.*.email            | string    | email    | ip@allbayrak.com                                                                                                                                                    |
| action_result.*.email_domain     | string    | domain   | allbayrak.com                                                                                                                                                       |
| action_result.*.referrer_domain  | string    | domain   | webmail.allbayrak.com                                                                                                                                               |
| action_result.*.referrer_ipv4    | string    | ip       | 46.173.218.219                                                                                                                                                      |
| action_result.*.referrer_url     | string    | url      | http://webmail.allbayrak.com/roundcube/?_task=mail&amp;_caps=pdf%3D1%2Cflash%3D0%2Ctiff%3D0%2Cwebp%3D1&amp;_uid=8&amp;_mbox=INBOX&amp;_framed=1&amp;_action=preview |
| action_result.*.sha256           | string    | sha256   | 281af32d4b70417c5027c9590f494aa9026c540a5c8af407dc3d464afe0a23ae                                                                                                    |
| action_result.parameter.domain   | string    | domain   | domain                                                                                                                                                              | 0 |
| action_result.status             | string    | status   | success Failed                                                                                                                                                      | 1 |
| action_result.message            | string    |
| summary.total_objects            | numeric   | 1        |
| summary.total_objects_successful | numeric   | 1        |

## action: 'lookup whois domain'

Perform this action to get the Whois Domain Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER  | REQUIRED | DESCRIPTION                                | TYPE | CONTAINS   |
|------------| -------- |--------------------------------------------| ---- |------------|
| **
domain** |  required  | Domain to get Lookup Data for Hyas Insight | string | `"domain"` |

#### Action Output

| data_path                                | data_type | contains   | example_values                                       |
|------------------------------------------|-----------|------------|------------------------------------------------------|
| action_result.param.domain               | string    | domain     | www.hyas.com                                         |
| action_result.*.datetime                 | string    |            | 2016-12-07T06:05:05.230927Z                          |
| action_result.*.whois_domain             | string    | domain     | hyas.com                                             |
| action_result.*.whois_abuse_email        | string    | email      | abuse@godaddy.com                                    |
| action_result.*.city                     | string    |            | scottsdale                                           |
| action_result.*.country                  | string    |            | US                                                   |
| action_result.*.address                  | string    |            | domainsbyproxy.com|14455 n. hayden road              |
| action_result.*.domain_2tld              | string    | domain     | hyas.com                                             |
| action_result.*.domain_created_datetime  | string    |            | 2001-05-02T00:00:00                                  |
| action_result.*.domain_expires_datetime  | string    |            | 2026-05-02T00:00:00                                  |
| action_result.*.domain_updated_datetime  | string    |            | 2017-06-28T04:45:22                                  |
| action_result.*.email                    | string    | email      | hyas.com@domainsbyproxy.com                          |
| action_result.*.idn_name                 | string    |            | None                                                 |
| action_result.*.name                     | string    |            | hyas                                                 |
| action_result.*.nameserver               | string    | nameserver | ['ns10.domaincontrol.com', 'ns09.domaincontrol.com'] |
| action_result.*.organization             | string    |            | hyas                                                 |
| action_result.*.phone_phone              | string    |            | +14806242599                                         |
| action_result.*.phone_phone_info_carrier | string    |            |                                                      |
| action_result.*.phone_phone_info_country | string    |            | United States                                        |
| action_result.*.phone_phone_info_geo     | string    |            | Arizona                                              |
| action_result.*.state                    | string    |            |                                                      |
| action_result.*.privacy_punch            | boolean   |            | False                                                |
| action_result.*.registrar                | string    |            | godaddy.com, llc                                     |
| action_result.parameter.domain           | string    | domain     | domain                                               | 0 |
| action_result.status                     | string    | status     | 1                                                    |
| action_result.message                    | string    |
| summary.total_objects                    | numeric   |
| summary.total_objects_successful         | numeric   |

## action: 'lookup whois email'

Perform this action to get the Whois Phone Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                                | TYPE | CONTAINS  |
|-----------| -------- |--------------------------------------------| ---- |-----------|
| **
email** |  required  | Domain to get Lookup Data for Hyas Insight | string | `"email"` |

#### Action Output

| data_path                                | data_type | contains   | example_values                                       |
|------------------------------------------|-----------|------------|------------------------------------------------------|
| action_result.param.domain               | string    | domain     | www.hyas.com                                         |
| action_result.*.datetime                 | string    |            | 2016-12-07T06:05:05.230927Z                          |
| action_result.*.whois_domain             | string    | domain     | hyas.com                                             |
| action_result.*.whois_abuse_email        | string    | email      | abuse@godaddy.com                                    |
| action_result.*.city                     | string    |            | scottsdale                                           |
| action_result.*.country                  | string    |            | US                                                   |
| action_result.*.address                  | string    |            | domainsbyproxy.com|14455 n. hayden road              |
| action_result.*.domain_2tld              | string    | domain     | hyas.com                                             |
| action_result.*.domain_created_datetime  | string    |            | 2001-05-02T00:00:00                                  |
| action_result.*.domain_expires_datetime  | string    |            | 2026-05-02T00:00:00                                  |
| action_result.*.domain_updated_datetime  | string    |            | 2017-06-28T04:45:22                                  |
| action_result.*.email                    | string    | email      | hyas.com@domainsbyproxy.com                          |
| action_result.*.idn_name                 | string    |            | None                                                 |
| action_result.*.name                     | string    |            | hyas                                                 |
| action_result.*.nameserver               | string    | nameserver | ['ns10.domaincontrol.com', 'ns09.domaincontrol.com'] |
| action_result.*.organization             | string    |            | hyas                                                 |
| action_result.*.phone_phone              | string    |            | +14806242599                                         |
| action_result.*.phone_phone_info_carrier | string    |            |                                                      |
| action_result.*.phone_phone_info_country | string    |            | United States                                        |
| action_result.*.phone_phone_info_geo     | string    |            | Arizona                                              |
| action_result.*.state                    | string    |            |                                                      |
| action_result.*.privacy_punch            | boolean   |            | False                                                |
| action_result.*.registrar                | string    |            | godaddy.com, llc                                     |
| action_result.parameter.domain           | string    | domain     | domain                                               | 0 |
| action_result.status                     | string    | status     | 1                                                    |
| action_result.message                    | string    |
| summary.total_objects                    | numeric   |
| summary.total_objects_successful         | numeric   |

## action: 'lookup whois phone'

Perform this action to get the Whois Phone Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                                | TYPE | CONTAINS  |
|-----------| -------- |--------------------------------------------| ---- |-----------|
| **
phone** |  required  | Domain to get Lookup Data for Hyas Insight | string | `"phone"` |

#### Action Output

| data_path                                | data_type | contains   | example_values                                       |
|------------------------------------------|-----------|------------|------------------------------------------------------|
| action_result.param.domain               | string    | domain     | www.hyas.com                                         |
| action_result.*.datetime                 | string    |            | 2016-12-07T06:05:05.230927Z                          |
| action_result.*.whois_domain             | string    | domain     | hyas.com                                             |
| action_result.*.whois_abuse_email        | string    | email      | abuse@godaddy.com                                    |
| action_result.*.city                     | string    |            | scottsdale                                           |
| action_result.*.country                  | string    |            | US                                                   |
| action_result.*.address                  | string    |            | domainsbyproxy.com|14455 n. hayden road              |
| action_result.*.domain_2tld              | string    | domain     | hyas.com                                             |
| action_result.*.domain_created_datetime  | string    |            | 2001-05-02T00:00:00                                  |
| action_result.*.domain_expires_datetime  | string    |            | 2026-05-02T00:00:00                                  |
| action_result.*.domain_updated_datetime  | string    |            | 2017-06-28T04:45:22                                  |
| action_result.*.email                    | string    | email      | hyas.com@domainsbyproxy.com                          |
| action_result.*.idn_name                 | string    |            | None                                                 |
| action_result.*.name                     | string    |            | hyas                                                 |
| action_result.*.nameserver               | string    | nameserver | ['ns10.domaincontrol.com', 'ns09.domaincontrol.com'] |
| action_result.*.organization             | string    |            | hyas                                                 |
| action_result.*.phone_phone              | string    |            | +14806242599                                         |
| action_result.*.phone_phone_info_carrier | string    |            |                                                      |
| action_result.*.phone_phone_info_country | string    |            | United States                                        |
| action_result.*.phone_phone_info_geo     | string    |            | Arizona                                              |
| action_result.*.state                    | string    |            |                                                      |
| action_result.*.privacy_punch            | boolean   |            | False                                                |
| action_result.*.registrar                | string    |            | godaddy.com, llc                                     |
| action_result.parameter.domain           | string    | domain     | domain                                               | 0 |
| action_result.status                     | string    | status     | 1                                                    |
| action_result.message                    | string    |
| summary.total_objects                    | numeric   |
| summary.total_objects_successful         | numeric   |

## action: 'lookup dynamicdns email'

Perform this action to get the Dynamicdns Email Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                               | TYPE | CONTAINS  |
|-----------| -------- |-------------------------------------------| ---- |-----------|
| **
email** |  required  | Email to get Lookup Data for Hyas Insight | string | `"email"` |

#### Action Output

| data_path                         | data_type | contains | example_values           |
|-----------------------------------|-----------|----------|--------------------------|
| action_result.parameter.email     | string    | email    | viendongonline@gmail.com |
| action_result.*.a_record          | string    |          | 4.4.4.4                  |
| action_result.*.account           | string    |          | free                     |
| action_result.*.created           | string    |          | 2022-03-14T11:05:14Z     |
| action_result.*.created_ip        | string    | ip       | 1.121.160.76             |
| action_result.*.domain            | string    | domain   | block-make.duckdns.org   |
| action_result.*.domain_creator_ip | string    | ip       | 101.185.25.219           |
| action_result.*.email             | string    | email    | DarkMagicSource@github   |
| action_result.parameter.email     | string    | email    | email                    | 0 |
| action_result.status              | string    | status   | 1                        |
| action_result.message             | string    |
| summary.total_objects             | numeric   |
| summary.total_objects_successful  | numeric   |

## action: 'lookup dynamicdns ip'

Perform this action to get the Dynamicdns IP Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                            | TYPE | CONTAINS |
|-----------| -------- |----------------------------------------| ---- |----------|
| **
ip**    |  required  | IP to get Lookup Data for Hyas Insight | string | `"ip"`   |

#### Action Output

| data_path                         | data_type | contains | example_values           |
|-----------------------------------|-----------|----------|--------------------------|
| action_result.parameter.email     | string    | email    | viendongonline@gmail.com |
| action_result.*.a_record          | string    |          | 4.4.4.4                  |
| action_result.*.account           | string    |          | free                     |
| action_result.*.created           | string    |          | 2022-03-14T11:05:14Z     |
| action_result.*.created_ip        | string    | ip       | 1.121.160.76             |
| action_result.*.domain            | string    | domain   | block-make.duckdns.org   |
| action_result.*.domain_creator_ip | string    | ip       | 101.185.25.219           |
| action_result.*.email             | string    | email    | DarkMagicSource@github   |
| action_result.parameter.email     | string    | email    | email                    | 0 |
| action_result.status              | string    | status   | 1                        |
| action_result.message             | string    |
| summary.total_objects             | numeric   |
| summary.total_objects_successful  | numeric   |

## action: 'lookup sinkhole ip'

Perform this action to get the Sinkhole IP Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                            | TYPE | CONTAINS |
|-----------| -------- |----------------------------------------| ---- |----------|
| **
ip**    |  required  | IP to get Lookup Data for Hyas Insight | string | `"ip"`   |

#### Action Output

| data_path                         | data_type | contains | example_values                    |
|-----------------------------------|-----------|----------|-----------------------------------|
| action_result.parameter.ip        | string    | ip       | 4.4.4.4                           |
| action_result.*.count             | string    |          | 4.4.4.4                           |
| action_result.*.country_name      | string    |          | Netherlands                       |
| action_result.*.data_port         | numeric   |          | 5552                              |
| action_result.*.datetime          | numeric   |          | 2020-06-25T00:08:32Z              |
| action_result.*.ipv4              | string    | ip       | 88.218.16.156                     |
| action_result.*.last_seen         | string    |          | 2020-06-25T00:08:32Z              |
| action_result.*.organization_name | string    |          | Shahkar Towse'e Tejarat Mana PJSC |
| action_result.*.sink_source       | string    |          | 192.169.69.25                     |
| action_result.parameter.ipv4      | string    | ip       | ipv4                              | 0 |
| action_result.status              | string    | status   | 1                                 |
| action_result.message             | string    |
| summary.total_objects             | numeric   |
| summary.total_objects_successful  | numeric   |

## action: 'lookup passivehash ip'

Perform this action to get the Passivehash IP Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                            | TYPE | CONTAINS |
|-----------| -------- |----------------------------------------| ---- |----------|
| **
ip**    |  required  | IP to get Lookup Data for Hyas Insight | string | `"ip"`   |

#### Action Output

| data_path                        | data_type | contains | example_values |
|----------------------------------|-----------|----------|----------------|
| action_result.parameter.ip       | string    | ip       | 192.169.69.25  |
| action_result.*.domain           | string    | domain   | wuxinewway.com |
| action_result.*.md5_count        | string    |          | 8              |
| action_result.parameter.ipv4     | string    | ip       | ipv4           | 0 |
| action_result.status             | string    | status   | 1              |
| action_result.message            | string    |
| summary.total_objects            | numeric   |
| summary.total_objects_successful | numeric   |

## action: 'lookup passivehash domain'

Perform this action to get the Passivehash Domain Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER  | REQUIRED | DESCRIPTION                                | TYPE | CONTAINS   |
|------------| -------- |--------------------------------------------| ---- |------------|
| **
domain** |  required  | Domain to get Lookup Data for Hyas Insight | string | `"domain"` |

#### Action Output

| data_path                        | data_type | contains | example_values |
|----------------------------------|-----------|----------|----------------|
| action_result.parameter.ip       | string    | ip       | 192.169.69.25  |
| action_result.*.domain           | string    | domain   | wuxinewway.com |
| action_result.*.md5_count        | string    |          | 8              |
| action_result.parameter.ipv4     | string    | ip       | ipv4           | 0 |
| action_result.status             | string    | status   | 1              |
| action_result.message            | string    |
| summary.total_objects            | numeric   |
| summary.total_objects_successful | numeric   |

## action: 'lookup ssl certificate ip'

Perform this action to get the SSL Certificate Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                            | TYPE | CONTAINS |
|-----------| -------- |----------------------------------------| ---- |----------|
| **
ip**    |  required  | IP to get Lookup Data for Hyas Insight | string | `"ip"`   |

#### Action Output

| data_path                                               | data_type | contains | example_values                                                   |
|---------------------------------------------------------|-----------|----------|------------------------------------------------------------------|
| action_result.parameter.ip                              | string    | ip       | 104.24.110.27                                                    |
| action_result.*.geo_geo_city_name                       | string    |          | San Francisco                                                    |
| action_result.*.geo_geo_country_iso_code                | string    |          | US                                                               |
| action_result.*.geo_geo_country_name                    | string    |          | United States                                                    |
| action_result.*.geo_geo_location_latitude               | string    |          | 37.7621                                                          |
| action_result.*.geo_geo_location_longitude              | string    |          | -122.3971                                                        |
| action_result.*.geo_geo_postal_code                     | string    |          | 94107                                                            |
| action_result.*.geo_isp_autonomous_system_number        | string    |          | AS13335                                                          |
| action_result.*.geo_isp_isp                             | string    |          | Cloudflare, Inc.                                                 |
| action_result.*.geo_isp_organization                    | string    |          | Cloudflare, Inc.                                                 |
| action_result.*.ip                                      | string    | ip       | 104.24.110.27                                                    |
| action_result.*.ssl_cert_cert_key                       | string    |          | 261757a2d2d31aa6dcabc27bb8b2395a207c6f52                         |
| action_result.*.ssl_cert_expire_date                    | string    |          | 2020-09-25T12:00:00Z                                             |
| action_result.*.ssl_cert_issue_date                     | string    |          | 2019-09-26T00:00:00Z                                             |
| action_result.*.ssl_cert_issuer_commonName              | string    |          | CloudFlare Inc ECC CA-2                                          |
| action_result.*.ssl_cert_issuer_countryName             | string    |          | US                                                               |
| action_result.*.ssl_cert_issuer_localityName            | string    |          | San Francisco                                                    |
| action_result.*.ssl_cert_issuer_organizationName        | string    |          | CloudFlare, Inc.                                                 |
| action_result.*.ssl_cert_issuer_organizationalUnitName  | string    |          |                                                                  |
| action_result.*.ssl_cert_issuer_stateOrProvinceName     | string    |          | CA                                                               |
| action_result.*.ssl_cert_md5                            | string    |          | 89c377cd36286e287b118a8013ba2296                                 |
| action_result.*.ssl_cert_serial_number                  | string    |          | 11233593787305851059064306644706338579                           |
| action_result.*.ssl_cert_sha1                           | string    |          | 261757a2d2d31aa6dcabc27bb8b2395a207c6f52                         |
| action_result.*.ssl_cert_sha_256                        | string    |          | 7118e559e93b9cf442f1c93fc9ed908f904c60d74fae82107b276b137cea5357 |
| action_result.*.ssl_cert_sig_algo                       | string    |          | ecdsa-with-sha256                                                |
| action_result.*.ssl_cert_ssl_version                    | string    |          | 2                                                                |
| action_result.*.ssl_cert_subject_commonName             | string    |          | sni.cloudflaressl.com                                            |
| action_result.*.ssl_cert_subject_countryName            | string    |          | US                                                               |
| action_result.*.ssl_cert_subject_localityName           | string    |          | San Francisco                                                    |
| action_result.*.ssl_cert_subject_organizationName       | string    |          | Cloudflare, Inc.                                                 |
| action_result.*.ssl_cert_subject_organizationalUnitName | string    |          |                                                                  |
| action_result.*.ssl_cert_subject_stateOrProvinceName    | string    |          | CA                                                               |
| action_result.*.ssl_cert_timestamp                      | string    |          | Thu, 26 Sep 2019 23:20:31 GMT                                    |
| action_result.parameter.ip                              | string    | ip,ipv6  | ip                                                               | 0 |
| action_result.status                                    | string    | status   | 1                                                                |
| action_result.message                                   | string    |
| summary.total_objects                                   | numeric   |
| summary.total_objects_successful                        | numeric   |

## action: 'lookup ssl certificate hash'

Perform this action to get the SSL Certificate Hash Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                              | TYPE | CONTAINS                             |
|-----------| -------- |------------------------------------------| ---- |--------------------------------------|
| **
hash**  |  required  | Hash to get Lookup Data for Hyas Insight | string | `"hash"` `"sha1"` `"sha256"` `"md5"` |

#### Action Output

| data_path                                               | data_type | contains | example_values                                                   |
|---------------------------------------------------------|-----------|----------|------------------------------------------------------------------|
| action_result.parameter.ip                              | string    | ip       | 104.24.110.27                                                    |
| action_result.*.geo_geo_city_name                       | string    |          | San Francisco                                                    |
| action_result.*.geo_geo_country_iso_code                | string    |          | US                                                               |
| action_result.*.geo_geo_country_name                    | string    |          | United States                                                    |
| action_result.*.geo_geo_location_latitude               | string    |          | 37.7621                                                          |
| action_result.*.geo_geo_location_longitude              | string    |          | -122.3971                                                        |
| action_result.*.geo_geo_postal_code                     | string    |          | 94107                                                            |
| action_result.*.geo_isp_autonomous_system_number        | string    |          | AS13335                                                          |
| action_result.*.geo_isp_isp                             | string    |          | Cloudflare, Inc.                                                 |
| action_result.*.geo_isp_organization                    | string    |          | Cloudflare, Inc.                                                 |
| action_result.*.ip                                      | string    | ip       | 104.24.110.27                                                    |
| action_result.*.ssl_cert_cert_key                       | string    |          | 261757a2d2d31aa6dcabc27bb8b2395a207c6f52                         |
| action_result.*.ssl_cert_expire_date                    | string    |          | 2020-09-25T12:00:00Z                                             |
| action_result.*.ssl_cert_issue_date                     | string    |          | 2019-09-26T00:00:00Z                                             |
| action_result.*.ssl_cert_issuer_commonName              | string    |          | CloudFlare Inc ECC CA-2                                          |
| action_result.*.ssl_cert_issuer_countryName             | string    |          | US                                                               |
| action_result.*.ssl_cert_issuer_localityName            | string    |          | San Francisco                                                    |
| action_result.*.ssl_cert_issuer_organizationName        | string    |          | CloudFlare, Inc.                                                 |
| action_result.*.ssl_cert_issuer_organizationalUnitName  | string    |          |                                                                  |
| action_result.*.ssl_cert_issuer_stateOrProvinceName     | string    |          | CA                                                               |
| action_result.*.ssl_cert_md5                            | string    |          | 89c377cd36286e287b118a8013ba2296                                 |
| action_result.*.ssl_cert_serial_number                  | string    |          | 11233593787305851059064306644706338579                           |
| action_result.*.ssl_cert_sha1                           | string    |          | 261757a2d2d31aa6dcabc27bb8b2395a207c6f52                         |
| action_result.*.ssl_cert_sha_256                        | string    |          | 7118e559e93b9cf442f1c93fc9ed908f904c60d74fae82107b276b137cea5357 |
| action_result.*.ssl_cert_sig_algo                       | string    |          | ecdsa-with-sha256                                                |
| action_result.*.ssl_cert_ssl_version                    | string    |          | 2                                                                |
| action_result.*.ssl_cert_subject_commonName             | string    |          | sni.cloudflaressl.com                                            |
| action_result.*.ssl_cert_subject_countryName            | string    |          | US                                                               |
| action_result.*.ssl_cert_subject_localityName           | string    |          | San Francisco                                                    |
| action_result.*.ssl_cert_subject_organizationName       | string    |          | Cloudflare, Inc.                                                 |
| action_result.*.ssl_cert_subject_organizationalUnitName | string    |          |                                                                  |
| action_result.*.ssl_cert_subject_stateOrProvinceName    | string    |          | CA                                                               |
| action_result.*.ssl_cert_timestamp                      | string    |          | Thu, 26 Sep 2019 23:20:31 GMT                                    |
| action_result.parameter.ip                              | string    | ip,ipv6  | ip                                                               | 0 |
| action_result.status                                    | string    | status   | 1                                                                |
| action_result.message                                   | string    |
| summary.total_objects                                   | numeric   |
| summary.total_objects_successful                        | numeric   |

## action: 'lookup passivedns domain'

Perform this action to get the Passivedns Domain Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER  | REQUIRED | DESCRIPTION                                | TYPE | CONTAINS   |
|------------| -------- |--------------------------------------------| ---- |------------|
| **
domain** |  required  | Domain to get Lookup Data for Hyas Insight | string | `"domain"` |

#### Action Output

| data_path                                             | data_type | contains | example_values                      |
|-------------------------------------------------------|-----------|----------|-------------------------------------|
| action_result.parameter.domain                        | string    | domain   | google.com                          |
| action_result.*.count                                 | string    |          | 1                                   |
| action_result.*.domain                                | string    | domain   | 189-70-45-212.user.veloxzone.com.br |
| action_result.*.first_seen                            | string    |          | 2014-07-30T00:00:00Z                |
| action_result.*.ip_geo_city_name                      | string    |          | Jaboatão dos Guararapes             |
| action_result.*.ip_geo_country_iso_code               | string    |          | BR                                  |
| action_result.*.ip_geo_country_name                   | string    |          | Brazil                              |
| action_result.*.ip_geo_location_latitude              | string    |          | -8.1128                             |
| action_result.*.ip_geo_location_longitude             | string    |          | -35.0147                            |
| action_result.*.ip_geo_postal_code                    | string    |          | 54000-000                           |
| action_result.*.ip_ip                                 | string    | ip       | 189.70.45.212                       |
| action_result.*.ip_isp_autonomous_system_number       | string    |          | AS7738                              |
| action_result.*.ip_isp_autonomous_system_organization | string    |          | Telemar Norte Leste S.A.            |
| action_result.*.ip_isp_ip_address                     | string    | ip       | 189.70.45.212                       |
| action_result.*.ip_isp_isp                            | string    |          | Telemar Norte Leste S.A.            |
| action_result.*.ip_isp_organization                   | string    |          | Telemar Norte Leste S.A.            |
| action_result.*.ipv4                                  | string    | ip       | 189.70.45.212                       |
| action_result.*.last_seen                             | string    |          | 2019-08-03T00:00:00Z                |
| action_result.*.sources                               | string    |          | zetalytics                          |
| action_result.parameter.domain                        | string    | domain   | domain                              | 0 |
| action_result.status                                  | string    | status   | 1                                   |
| action_result.message                                 | string    |
| summary.total_objects                                 | numeric   |
| summary.total_objects_successful                      | numeric   |

## action: 'lookup passivedns ip'

Perform this action to get the Passivedns IP Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                            | TYPE | CONTAINS |
|-----------| -------- |----------------------------------------| ---- |----------|
| **
ip**    |  required  | IP to get Lookup Data for Hyas Insight | string | `"ip"`   |

#### Action Output

| data_path                                             | data_type | contains | example_values                      |
|-------------------------------------------------------|-----------|----------|-------------------------------------|
| action_result.parameter.domain                        | string    | domain   | google.com                          |
| action_result.*.count                                 | string    |          | 1                                   |
| action_result.*.domain                                | string    | domain   | 189-70-45-212.user.veloxzone.com.br |
| action_result.*.first_seen                            | string    |          | 2014-07-30T00:00:00Z                |
| action_result.*.ip_geo_city_name                      | string    |          | Jaboatão dos Guararapes             |
| action_result.*.ip_geo_country_iso_code               | string    |          | BR                                  |
| action_result.*.ip_geo_country_name                   | string    |          | Brazil                              |
| action_result.*.ip_geo_location_latitude              | string    |          | -8.1128                             |
| action_result.*.ip_geo_location_longitude             | string    |          | -35.0147                            |
| action_result.*.ip_geo_postal_code                    | string    |          | 54000-000                           |
| action_result.*.ip_ip                                 | string    | ip       | 189.70.45.212                       |
| action_result.*.ip_isp_autonomous_system_number       | string    |          | AS7738                              |
| action_result.*.ip_isp_autonomous_system_organization | string    |          | Telemar Norte Leste S.A.            |
| action_result.*.ip_isp_ip_address                     | string    | ip       | 189.70.45.212                       |
| action_result.*.ip_isp_isp                            | string    |          | Telemar Norte Leste S.A.            |
| action_result.*.ip_isp_organization                   | string    |          | Telemar Norte Leste S.A.            |
| action_result.*.ipv4                                  | string    | ip       | 189.70.45.212                       |
| action_result.*.last_seen                             | string    |          | 2019-08-03T00:00:00Z                |
| action_result.*.sources                               | string    |          | zetalytics                          |
| action_result.parameter.domain                        | string    | domain   | domain                              | 0 |
| action_result.status                                  | string    | status   | 1                                   |
| action_result.message                                 | string    |
| summary.total_objects                                 | numeric   |
| summary.total_objects_successful                      | numeric   |

## action: 'lookup current whois domain'

Perform this action to get the Whois current Domain Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER  | REQUIRED | DESCRIPTION                                | TYPE | CONTAINS   |
|------------| -------- |--------------------------------------------| ---- |------------|
| **
domain** |  required  | Domain to get Lookup Data for Hyas Insight | string | `"domain"` |

#### Action Output

| data_path                                     | data_type | contains   | example_values                                                                                   |
|-----------------------------------------------|-----------|------------|--------------------------------------------------------------------------------------------------|
| action_result.parameter.domain                | string    | domain     | google.com                                                                                       |
| action_result.*.datetime                      | string    |            | 2022-03-14T11:05:14Z                                                                             |
| action_result.*.domain                        | string    | domain     | hyas.com                                                                                         |
| action_result.*.abuse_emails                  | string    | email      | abuse@godaddy.com                                                                                |
| action_result.*.address                       | string    |            | Domainsbyproxy.com
2155 E Warner Rd                                                              |
| action_result.*.city                          | string    |            | Temple                                                                                           |
| action_result.*.country                       | string    |            | United States                                                                                    |
| action_result.*.domain_2tld                   | string    | domain     | hyas.com                                                                                         |
| action_result.*.domain_created_datetime       | string    |            | 2001-05-01T23:42:14                                                                              |
| action_result.*.domain_expires_datetime       | string    |            | 2026-05-01T23:42:14                                                                              |
| action_result.*.domain_updated_datetime       | string    |            | 2020-06-30T17:43:35                                                                              |
| action_result.*.email                         | string    | email      | abuse@godaddy.com                                                                                |
| action_result.*.idn_name                      | string    |            | None                                                                                             |
| action_result.*.name                          | string    |            | Registration                                                                                     |
| action_result.*.nameserver                    | string    | nameserver | ns10.domaincontrol.com                                                                           |
| action_result.*.organization                  | string    |            | Domains By Proxy, LLC                                                                            |
| action_result.*.phone                         | string    | phone      | +14806242599                                                                                     |
| action_result.*.state                         | string    |            | Arizona                                                                                          |
| action_result.*.registrar                     | string    |            | whois_pii_city godaddy.com, llc                                                                  |
| action_result.*.whois_nameserver_domain       | string    |            | ns10.domaincontrol.com                                                                           |
| action_result.*.whois_pii_address             | string    |            | Domainsbyproxy.com 2155 E Warner Rd                                                              |
| action_result.*.whois_pii_city                | string    |            | Temple                                                                                           |
| action_result.*.whois_pii_email               | string    |            | select contact domain holder link at https://www.godaddy.com/whois/results.aspx?domain=hyas.com  |
| action_result.*.whois_pii_name                | string    |            | Registration Private                                                                             |
| action_result.*.whois_pii_organization        | string    |            | Domains By Proxy, LLC                                                                            |
| action_result.*.whois_pii_state               | string    |            | Arizona                                                                                          |
| action_result.*.whois_pii_geo_country_alpha_2 | string    |            | United States                                                                                    |
| action_result.*.whois_pii_phone_e164          | string    |            | +14806242599                                                                                     |
| action_result.*.privacy_punch                 | string    |            | False                                                                                            |
| action_result.parameter.domain                | string    | domain     | domain                                                                                           | 0 |
| action_result.status                          | string    | status     | 1                                                                                                |
| action_result.message                         | string    |
| summary.total_objects                         | numeric   |
| summary.total_objects_successful              | numeric   |

## action: 'lookup malware information hash'

Perform this action to get the Malware Information Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                              | TYPE | CONTAINS |
|-----------| -------- |------------------------------------------| ---- |----------|
| **
hash**  |  required  | Hash to get Lookup Data for Hyas Insight | string | `"hash"` |

#### Action Output

| data_path                                | data_type | contains | example_values         |
|------------------------------------------|-----------|----------|------------------------|
| action_result.*.scan_result_av_name      | string    |          | Quick Heal             |
| action_result.*.scan_result_def_time     | string    |          | 2017-03-07T00:00:00Z   |
| action_result.*.scan_result_threat_found | string    |          | Backdoor.Zegost.MUE.A8 |
| action_result.parameter.hash             | string    | md5      | hash                   | 0 |
| action_result.status                     | string    | status   | 1                      |
| action_result.message                    | string    |
| summary.total_objects                    | numeric   |
| summary.total_objects_successful         | numeric   |

## action: 'lookup malware record hash'

Perform this action to get the Malware Record hash Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                              | TYPE | CONTAINS |
|-----------| -------- |------------------------------------------| ---- |----------|
| **
hash**  |  required  | Hash to get Lookup Data for Hyas Insight | string | `"hash"` |

#### Action Output

| data_path                        | data_type | contains             | example_values                   |
|----------------------------------|-----------|----------------------|----------------------------------|
| action_result.*.datetime         | string    |                      | 2017-03-07T00:00:00Z             |
| action_result.*.domain           | string    | domain               | butterfly.sinip.es               |
| action_result.*.md5              | string    | hash                 | 1d0a97c41afe5540edd0a8c1fb9a0f1c |
| action_result.parameter.hash     | string    | hash,md5,sha256,sha1 | hash                             | 0 |
| action_result.status             | string    | status               | 1                                |
| action_result.message            | string    |
| summary.total_objects            | numeric   |
| summary.total_objects_successful | numeric   |

## action: 'lookup os indicator hash'

Perform this action to get the OS Indicator Lookup Data for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                              | TYPE | CONTAINS |
|-----------| -------- |------------------------------------------| ---- |----------|
| **
hash**  |  required  | Hash to get Lookup Data for Hyas Insight | string | `"hash"` |

#### Action Output

| data_path                               | data_type | contains             | example_values                                                   |
|-----------------------------------------|-----------|----------------------|------------------------------------------------------------------|
| action_result.*.context                 | string    |                      |                                                                  |
| action_result.*.data                    | string    |                      |                                                                  |
| action_result.*.datetime                | string    |                      | 2022-06-28T08:02:19.942Z                                         |
| action_result.*.domain                  | string    | domain               | google.com                                                       |
| action_result.*.domain_2tld             | string    |                      |                                                                  |
| action_result.*.first_seen              | string    |                      | 2022-06-28T08:02:19.942Z                                         |
| action_result.*.ipv4                    | string    | ipv4                 | 4.4.4.4                                                          |
| action_result.*.ipv6                    | string    | ipv6                 | fe80::be54:51ff:feeb:bf98                                        |
| action_result.*.last_seen               | string    |                      | 2022-06-28T08:07:09.083Z                                         |
| action_result.*.md5                     | string    |                      |                                                                  |
| action_result.*.os_indicators_id        | string    |                      |                                                                  |
| action_result.*.os_indicators_source_id | string    |                      |                                                                  |
| action_result.*.sha1                    | string    | hash                 | 31fc5acafc10fe5743d03ebec268fbcd62ed5ac6                         |
| action_result.*.sha256                  | string    | hash                 | 281af32d4b70417c5027c9590f494aa9026c540a5c8af407dc3d464afe0a23ae |
| action_result.*.source_name             | string    |                      | Rapid7 Open Data SSL Certificates                                |
| action_result.*.source_url              | string    |                      | https://opendata.rapid7.com/sonar.ssl/                           |
| action_result.*.uri                     | string    |                      |                                                                  |
| action_result.parameter.hash            | string    | hash,md5,sha1,sha256 | hash                                                             | 0 |
| action_result.status                    | string    | status               | 1                                                                |
| action_result.message                   | string    |
| summary.total_objects                   | numeric   |
| summary.total_objects_successful        | numeric   |

## action: 'lookup Mobile Geolocation Information ipv4'

Perform this action to get the Mobile Geolocation Information IPv4 Lookup Data
for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                              | TYPE | CONTAINS |
|-----------| -------- |------------------------------------------| ---- |----------|
| **
ipv4**  |  required  | IPv4 to get Lookup Data for Hyas Insight | string | `"ipv4"` |

#### Action Output

| data_path                               | data_type | contains | column_name                          | column_order |
|-----------------------------------------|-----------|----------|--------------------------------------|--------------|
| action_result.parameter.ipv4            | string    | ip       | ipv4                                 | 0            |
| action_result.*.datetime                | string    |          | 2020-07-09T09:53:35Z                 |
| action_result.*.device_geo_id           | string    |          | 9120a69e-cc23-451a-a55d-4223e0cec88b |
| action_result.*.device_user_agent       | string    |          | 15.3.1                               |
| action_result.*.geo_country_alpha_2     | numeric   |          | AU                                   |
| action_result.*.geo_horizontal_accuracy | string    |          | 15.6                                 |
| action_result.*.ipv4                    | string    |          | 1.157.132.70                         |
| action_result.*.ipv6                    | string    |          | fe80::be54:51ff:feeb:bf98            |
| action_result.*.latitude                | numeric   |          | -33.732083                           |
| action_result.*.longitude               | numeric   |          | 151.156693                           |
| action_result.*.wifi_bssid              | numeric   |          | bc:30:d9:cd:3b:fe                    |
| action_result.status                    | string    | status   | 1                                    |
| action_result.message                   | string    |
| summary.total_objects                   | numeric   |
| summary.total_objects_successful        | numeric   |

## action: 'lookup Mobile Geolocation Information ipv6'

Perform this action to get the Mobile Geolocation Information IPv6 Lookup Data
for Hyas Insight

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION                              | TYPE | CONTAINS |
|-----------| -------- |------------------------------------------| ---- |----------|
| **
ipv6**  |  required  | IPv6 to get Lookup Data for Hyas Insight | string | `"ipv6"` |

#### Action Output

| data_path                               | data_type | contains | column_name                          | column_order |
|-----------------------------------------|-----------|----------|--------------------------------------|--------------|
| action_result.parameter.ipv4            | string    | ip       | ipv4                                 | 0            |
| action_result.*.datetime                | string    |          | 2020-07-09T09:53:35Z                 |
| action_result.*.device_geo_id           | string    |          | 9120a69e-cc23-451a-a55d-4223e0cec88b |
| action_result.*.device_user_agent       | string    |          | 15.3.1                               |
| action_result.*.geo_country_alpha_2     | numeric   |          | AU                                   |
| action_result.*.geo_horizontal_accuracy | string    |          | 15.6                                 |
| action_result.*.ipv4                    | string    |          | 1.157.132.70                         |
| action_result.*.ipv6                    | string    |          | fe80::be54:51ff:feeb:bf98            |
| action_result.*.latitude                | numeric   |          | -33.732083                           |
| action_result.*.longitude               | numeric   |          | 151.156693                           |
| action_result.*.wifi_bssid              | numeric   |          | bc:30:d9:cd:3b:fe                    |
| action_result.status                    | string    | status   | 1                                    |
| action_result.message                   | string    |
| summary.total_objects                   | numeric   |
| summary.total_objects_successful        | numeric   |