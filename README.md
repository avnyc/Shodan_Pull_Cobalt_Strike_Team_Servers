# Shodan_Pull_Cobalt_Strike_Team_Servers
This code will pull Cobalt Strike Team Servers from Shodan's API using various criteria.
I want to thank Mike Koczwara for all his work. You can check him out here: https://michaelkoczwara.medium.com/ and here: https://twitter.com/MichalKoczwara. 
I want to thank another Mike for pointing me to Shodan. The man has forgotten more knowledge than I currently have so I am grateful. 
I want to thank Salesforce for their jarm tool
I want to thank this github page for their jarm list: https://github.com/carbonblack/active_c2_ioc_public/blob/main/cobaltstrike/JARM/jarm_cs_202107_uniq_sorted.txt

The code has 6 main functions:
  1. shodan_team_server_basic()
  2. shodan_team_server_certificates()
  3. shodan_team_server_watermarks()
  4. shodan_team_server_port_hash()
  5. shodan_team_server_jarm_and_defaults()
  6. ip_domain_hostname_aggregator()
 
