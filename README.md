# Shodan_Pull_Cobalt_Strike_Team_Servers
This code will pull Cobalt Strike Team Servers from Shodan's API using various criteria.
I want to thank Mike Koczwara for all his work. You can check him out here: https://michaelkoczwara.medium.com/ and here: https://twitter.com/MichalKoczwara. 
I want to thank another Mike for pointing me to Shodan. The man has forgotten more knowledge than I currently have. I am grateful for all the knowledge transfer. Mike, if you read this, and you want me to add your last name - let me know. Right now no one is viewing these repositories.
I want to thank Salesforce for creating JARM.
I want to thank this github page for their JARM list: https://github.com/carbonblack/active_c2_ioc_public/blob/main/cobaltstrike/JARM/jarm_cs_202107_uniq_sorted.txt.
I want to thank Shodan for their data. The results are theirs.
I am currently paying for the Freelancer API. I don't have access to the higher tiers. 

This code will be revamped! This is NOT the final version. I plan on modifying results with the CN field and breaking out the domains for our DNS tool among others.

The code has 7 main functions:
  1. shodan_team_server_basic()
  2. shodan_team_server_certificates()
  3. shodan_team_server_watermarks()
  4. shodan_team_server_port_hash()
  5. shodan_team_server_jarm_and_defaults()
  6. team_server_hostname_aggregator()
  7. metasploit()
 
