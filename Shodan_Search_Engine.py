from file_locations import shodan_logger, shodan_cobalt_strike_simplified_export_csv, \
    shodan_cobalt_strike_certificate_export_csv, shodan_cobalt_strike_watermark_export_csv, \
    shodan_cobalt_strike_port_hash_export_csv, shodan_cobalt_strike_port_jarm_and_defaults_csv, \
    shodan_hosts_csv, shodan_metasploit_csv, shodan_main_aggregator_csv
import os
import pandas as pd
import shodan
from shodan import Shodan
import time

# Create start time
start_time = time.time()

# Make df more reader friendly in 'Run' window
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('expand_frame_repr', False)


class ShodanSearchEngine:
    # Cobalt Strike Characteristics
    shodan_cobalt_strike_search_simplified = 'product:Cobalt Strike Beacon'  # Easiest and low false-positive search

    # These certs when tested on 12/2/22, 12/3/22, & 12/4/22 returned less than 400 total results without other filters
    cobalt_strike_certificates = [
        'ssl.cert.serial:146473198',   # This is the default Team Server Serial
        'ssl.cert.serial:305419896',   # Cracked version
        'ssl.cert.serial:1873433027',  # Cracked version
        'ssl.cert.serial:16777216',    # Cracked version
        'ssl.cert.serial:1359593325',  # Cracked version
        'ssl.cert.serial:8BB00EE'
        'ssl.6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C'
        ]

    cobalt_strike_watermarks = [
        'watermark:-1879048192',
        'watermark:0',
        'watermark:1',
        'watermark:6',
        'watermark:8848',
        'watermark:12345',
        'watermark:100000',
        'watermark:574247',
        'watermark:666666',
        'watermark:1755231',
        'watermark:16777216',
        'watermark:76803050',
        'watermark:206546002',
        'watermark:305419896',
        'watermark:391144938',
        'watermark:426352781',
        'watermark:668694132',
        'watermark:674054486',
        'watermark:987654321',
        'watermark:1234567890',
        'watermark:1359593325',
        'watermark:1359593325',
        'watermark:1580103814',
        'watermark:1580103824',
        'watermark:1873433027',
        'watermark:2130772225',
        ]

    # Use both port and hash in conjunction
    cobalt_strike_port = 'port:50050'
    cobalt_strike_hash = 'hash:-2007783223'

    # Use the below to filter JARMS. JARMS without additional filters will return too many values
    cobalt_strike_content_length = 'Content-Length:0'
    cobalt_strike_content_type = 'Content-Type: text/plain'
    cobalt_strike_default_404_response = 'HTTP/1.1 404 Not Found'

    Cobalt_Strike_JARMS = [
        '00014d16d21d21d00042d41d00041df1e57cd0b3bf64d18696fb4fce056610',
        '00014d16d21d21d07c42d41d00041d47e4e0ae17960b2a5b4fd6107fbb0926',
        '05d02d16d04d04d05c05d02d05d04d4606ef7946105f20b303b9a05200e829',
        '05d02d20d21d20d05c05d02d05d20dd7fc4c7c6ef19b77a4ca0787979cdc13',
        '05d13d20d21d20d05c05d13d05d20dd7fc4c7c6ef19b77a4ca0787979cdc13',
        '07d00016d21d21d00042d41d00041df1e57cd0b3bf64d18696fb4fce056610',
        '07d0bd0fd06d06d07c07d0bd07d06d9b2f5869a6985368a9dec764186a9175',
        '07d0bd0fd21d21d07c07d0bd07d21d9b2f5869a6985368a9dec764186a9175',
        '07d13d15d21d21d07c07d13d07d21dd7fc4c7c6ef19b77a4ca0787979cdc13',
        '07d14d16d21d21d00007d14d07d21d3fe87b802002478c27f1c0da514dbf80',
        '07d14d16d21d21d00042d41d00041d47e4e0ae17960b2a5b4fd6107fbb0926',
        '07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2',
        '07d14d16d21d21d07c07d14d07d21d4606ef7946105f20b303b9a05200e829',
        '07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175',
        '07d14d16d21d21d07c07d14d07d21dee4eea372f163361c2623582546d06f8',
        '07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1',
        '07d14d16d21d21d07c42d41d00041d58c7162162b6a603d3d90a2b76865b53',
        '07d14d16d21d21d07c42d43d00041d24a458a375eef0c576d23a7bab9a9fb1',
        '07d19d1ad21d21d00007d19d07d21d25f4195751c61467fa54caf42f4e2e61',
        '15d15d15d3fd15d00042d42d00042d1279af56d3d287bbc5d38e226153ba9e',
        '15d3fd16d21d21d00042d43d000000fe02290512647416dcf0a400ccbc0b6b',
        '15d3fd16d29d29d00015d3fd15d29d1f9d8d2d24bf6c1a8572e99c89f1f5f0',
        '15d3fd16d29d29d00042d43d000000ed1cf37c9a169b41886e27ba8fad60b0',
        '15d3fd16d29d29d00042d43d000000fbc10435df141b3459e26f69e76d5947',
        '15d3fd16d29d29d00042d43d000000fe02290512647416dcf0a400ccbc0b6b',
        '16d16d16d00000022c43d43d00043d370cd49656587484eb806b90846875a0',
        '1dd28d28d00028d00042d41d00041df1e57cd0b3bf64d18696fb4fce056610',
        '1dd28d28d00028d1dc1dd28d1dd28d3fe87b802002478c27f1c0da514dbf80',
        '21b10b00021b21b21b21b10b21b21b3b0d229d76f2fd7cb8e23bb87da38a20',
        '21d10d00021d21d21c21d10d21d21d696c1bb221f80034f540b6754152d3b8',
        '21d19d00021d21d21c42d43d000000624c0617d7b1f32125cdb5240cd23ec9',
        '29d29d00029d29d00029d29d29d29de1a3c0d7ca6ad8388057924be83dfc6a',
        '29d29d00029d29d08c29d29d29d29dcd113334714fbefb4b0aba4000bcef62',
        '29d29d00029d29d21c29d29d29d29dce7a321e4956e8298ba917e9f2c22849',
        '29d29d15d29d29d21c29d29d29d29d7329fbe92d446436f2394e041278b8b2',
        '2ad00016d2ad2ad22c42d42d00042ddb04deffa1705e2edc44cae1ed24a4da',
        '2ad2ad0002ad2ad0002ad2ad2ad2ade1a3c0d7ca6ad8388057924be83dfc6a',
        '2ad2ad0002ad2ad00042d42d000000301510f56407964db9434a9bb0d4ee4a',
        '2ad2ad0002ad2ad00042d42d0000005d86ccb1a0567e012264097a0315d7a7',
        '2ad2ad0002ad2ad22c2ad2ad2ad2ad6a7bd8f51d54bfc07e1cd34e5ca50bb3',
        '2ad2ad0002ad2ad22c2ad2ad2ad2adce7a321e4956e8298ba917e9f2c22849',
        '2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da',
        '2ad2ad16d2ad2ad22c42d42d00042d58c7162162b6a603d3d90a2b76865b53',
        '2ad2ad16d2ad2ad22c42d42d00042de4f6cde49b80ad1e14c340f9e47ccd3a',
        '3fd3fd15d3fd3fd00042d42d00000061256d32ed7779c14686ad100544dc8d',
        '3fd3fd15d3fd3fd21c3fd3fd3fd3fdc110bab2c0a19e5d4e587c17ce497b15',
        '3fd3fd15d3fd3fd21c42d42d0000006f254909a73bf62f6b28507e9fb451b5'
    ]

    def __init__(self, api_value):
        self.api = Shodan(api_value)
        self.cobalt_strike_simplified_df = pd.DataFrame()
        self.main_certificate_df = pd.DataFrame()
        self.watermark_df = pd.DataFrame()
        self.port_hash_df = pd.DataFrame()
        self.main_jarm_df = pd.DataFrame()
        self.metasploit_df = pd.DataFrame()
        self.columns_to_keep = ['ip_str', 'hostnames']
        self.metasploit_columns_to_keep = ['ip_str', 'hostnames', 'Server_Type']
        self.shodan_team_server_basic()
        self.shodan_team_server_certificates()
        self.shodan_team_server_watermarks()
        self.shodan_team_server_port_hash()
        self.shodan_team_server_jarm_and_defaults()
        self.metasploit_cn = 'ssl.cert.issuer.cn:MetasploitSelfSignedCA'
        self.metasploit_port = 'port:3790'
        self.metasploit()

        # Aggregate all information
        self.hostname_aggregator()

    def shodan_team_server_basic(self):
        try:
            # Pull results
            results = self.api.search_cursor(f'{ShodanSearchEngine.shodan_cobalt_strike_search_simplified}')
            # Import generator into df
            cobalt_strike_simplified_df = pd.DataFrame(results)
            # Send df to file location
            cobalt_strike_simplified_df.to_csv(shodan_cobalt_strike_simplified_export_csv, index=False)

            shodan_logger.info(f'Total default simplified Cobalt Strike results are '
                               f'{cobalt_strike_simplified_df.shape[0]}')
            shodan_logger.info(f'Code took {((time.time() - start_time) / 60):.3f} minutes to execute so far.')
            shodan_logger.info(f'-------------------------------------------------------------------------------------')
            shodan_logger.info(f'\n')

            # Return cobalt_strike_simplified_df
            self.cobalt_strike_simplified_df = cobalt_strike_simplified_df[self.columns_to_keep]

        except ShodanSearchEngine.APIError as e:
            logging.error(f'The Shodan API Error for simplified default is: {e}')

    def shodan_team_server_certificates(self):
        try:
            # Loop through Cobalt Strike Certificates
            for certificate in ShodanSearchEngine.cobalt_strike_certificates:
                # Return results
                results = self.api.search_cursor(f'{certificate}')
                # Create certificate df from results
                certificate_df = pd.DataFrame(results)
                # If we find any results append to main df
                if certificate_df.shape[0] != 0:
                    # main_certificate_df = main_certificate_df.append(certificate_df)
                    self.main_certificate_df = pd.concat([self.main_certificate_df, certificate_df], ignore_index=True,
                                                         sort=False)
                    shodan_logger.info(f'Total certificate Cobalt Strike results are {certificate_df.shape[0]} '
                                       f'for {certificate}')
                else:
                    shodan_logger.warning(f'Total certificate Cobalt Strike results are {certificate_df.shape[0]} '
                                          f'for {certificate}')

            # Send Cobalt Strike Certificate Export file
            self.main_certificate_df.to_csv(shodan_cobalt_strike_certificate_export_csv, index=False)
            # Logger info
            shodan_logger.info(f'Total Cobalt Strike servers found via default and cracked certificates are '
                               f'{self.main_certificate_df.shape[0]}')
            shodan_logger.info(f'Code took {((time.time() - start_time) / 60):.3f} minutes to execute so far.')
            shodan_logger.info(f'-------------------------------------------------------------------------------------')
            shodan_logger.info(f'\n')

            # Return main_certificate_df
            self.main_certificate_df = self.main_certificate_df[self.columns_to_keep]

        except ShodanSearchEngine.APIError as e:
            shodan_logger.error(f'The Shodan API Error certificate is: {e}')

    def shodan_team_server_watermarks(self):
        try:
            for watermark in ShodanSearchEngine.cobalt_strike_watermarks:
                results = self.api.search_cursor(f'{watermark}')
                # Create watermark df from results
                watermark_df = pd.DataFrame(results)
                # Send Cobalt Strike Watermark Export file
                watermark_df.to_csv(shodan_cobalt_strike_watermark_export_csv, index=False)
                # Logger info
                shodan_logger.info(f'Total Cobalt Strike servers found via {watermark} are {watermark_df.shape[0]}')
                shodan_logger.info(f'Code took {((time.time() - start_time) / 60):.3f} minutes to execute so far.')
                shodan_logger.info(f'---------------------------------------------------------------------------------')
                shodan_logger.info(f'\n')

            # Return watermark df
            self.watermark_df = watermark_df[self.columns_to_keep]

        except ShodanSearchEngine.APIError as e:
            shodan_logger.error(f'The Shodan API Error for watermark is: {e}')

    def shodan_team_server_port_hash(self):
        try:
            results = self.api.search_cursor(f'{ShodanSearchEngine.cobalt_strike_port} '
                                             f'{ShodanSearchEngine.cobalt_strike_hash}')
            # Create Cobalt Strike Port Hash df
            port_hash_df = pd.DataFrame(results)

            # Send Cobalt Strike Port Hash Export file
            port_hash_df.to_csv(shodan_cobalt_strike_port_hash_export_csv, index=False)
            # Logger info
            shodan_logger.info(f'Total Cobalt Strike servers found via {ShodanSearchEngine.cobalt_strike_port} & '
                               f'{ShodanSearchEngine.cobalt_strike_hash} is '
                               f'{port_hash_df.shape[0]}')
            shodan_logger.info(f'Code took {((time.time() - start_time) / 60):.3f} minutes to execute so far.')
            shodan_logger.info(f'------------------------------------------------------------------------------------')
            shodan_logger.info(f'\n')

            # Return port_hash_df
            self.port_hash_df = port_hash_df[self.columns_to_keep]

        except ShodanSearchEngine.APIError as e:
            logging.error(f'The Shodan API Error for port hash is: {e}')

    def shodan_team_server_jarm_and_defaults(self):
        try:
            # Create main_jarm_df
            main_jarm_df = pd.DataFrame()
            for jarm in ShodanSearchEngine.Cobalt_Strike_JARMS:
                results = self.api.search_cursor(f'ssl.jarm:{jarm} '
                                                 f'{ShodanSearchEngine.cobalt_strike_content_length} '
                                                 f'{ShodanSearchEngine.cobalt_strike_content_type} ' 
                                                 f'{ShodanSearchEngine.cobalt_strike_default_404_response}')

                temp_jarm_df = pd.DataFrame(results)
                if temp_jarm_df.shape[0] != 0:
                    # Concat main and temporary df
                    main_jarm_df = pd.concat([main_jarm_df, temp_jarm_df], ignore_index=True, sort=False)
                    shodan_logger.info(
                        f'Cobalt Strike results from jarm {jarm} and default settings is '
                        f'{temp_jarm_df.shape[0]}')

                else:
                    shodan_logger.warning(f'No results found for jarm {jarm} and default settings. Total count remains '
                                          f'the same at {main_jarm_df.shape[0]}')
            shodan_logger.info(f'Code took {((time.time() - start_time) / 60):.3f} minutes to execute so far.')
            shodan_logger.info(f'-------------------------------------------------------------------------------------')
            shodan_logger.info(f'\n')
            # Export main_jarm_df to CSV
            main_jarm_df.to_csv(shodan_cobalt_strike_port_jarm_and_defaults_csv, index=False)
            # Return main_jarm_df
            self.main_jarm_df = main_jarm_df[self.columns_to_keep]

        except ShodanSearchEngine.APIError as e:
            logging.error(f'The Shodan API Error for jarm and defaults is: {e}')
            
    def metasploit(self):
        try:
            results = self.api.search_cursor(f'{self.metasploit_cn} '
                                             f'{self.metasploit_port}')
            # Create metasploit_df from results
            metasploit_df = pd.DataFrame(results)
            # Send Metasploit Export file
            metasploit_df[self.columns_to_keep].to_csv(shodan_metasploit_csv, index=False)
            # Logger info
            shodan_logger.info(f'Total Metasploit servers found via {self.metasploit_cn} '
                               f'and {self.metasploit_port} are: {metasploit_df.shape[0]}')
            shodan_logger.info(f'Code took {((time.time() - start_time) / 60):.3f} minutes to execute.')
            shodan_logger.info(f'---------------------------------------------------------------------------------')
            shodan_logger.info(f'\n')

            # Return metasploit_df
            metasploit_df['Server_Type'] = 'Metasploit Server'
            self.metasploit_df = metasploit_df[self.metasploit_columns_to_keep]
        except ShodanSearchEngine.APIError as e:
            shodan_logger.error(f'The Shodan API Error for Metasploit is: {e}')

    def hostname_aggregator(self):
        try:
            master_df = pd.DataFrame()
            master_df = pd.concat([master_df, self.cobalt_strike_simplified_df], ignore_index=True, sort=False)
            master_df = pd.concat([master_df, self.main_certificate_df], ignore_index=True, sort=False)
            master_df = pd.concat([master_df, self.watermark_df], ignore_index=True, sort=False)
            master_df = pd.concat([master_df, self.port_hash_df], ignore_index=True, sort=False)
            master_df = pd.concat([master_df, self.main_jarm_df], ignore_index=True, sort=False)

            # Create new column for Cobalt Strike Team Servers
            master_df['Server_Type'] = 'Cobalt Strike Team Server'

            master_df = pd.concat([master_df, self.metasploit_df], ignore_index=True, sort=False)

            # Remove duplicates in 'ip_str'
            shodan_logger.info(f'Total malicious IPs before dropping duplicates is {master_df.shape[0]}')
            master_df = master_df.drop_duplicates(subset='ip_str', keep='first')
            shodan_logger.info(f'Total malicious IPs after dropping duplicates is {master_df.shape[0]}')
            master_df.to_csv(shodan_main_aggregator_csv, index=False)

            shodan_logger.info(f'Rows before manipulation are: {master_df.shape[0]}')

            master_df = master_df.explode('hostnames')
            master_df['hostnames'] = master_df['hostnames'].astype(str)
            # master_df = master_df.drop(df[~(df['hostnames'] != '[]')].index)
            shodan_logger.info(f'Rows after removing empty lists are: {master_df.shape[0]}')
            master_df['hostnames'] = master_df['hostnames'].astype(str)
            master_df['hostnames'] = master_df['hostnames'].str.replace('[', '', regex=False)
            master_df['hostnames'] = master_df['hostnames'].str.replace(']', '', regex=False)
            master_df['hostnames'] = master_df['hostnames'].str.replace("'", "", regex=False)
            master_df['hostnames'] = master_df['hostnames'].str.replace(" ", "", regex=False)
            master_df = master_df.sort_values(by=['hostnames'])
            master_df = master_df['hostnames'].str.split(',').explode('hostnames').reset_index(drop=True)
            shodan_logger.info(f'Rows after exploding lists are: {master_df.shape[0]}')
            shodan_logger.info(f'Before duplicates are dropped are: {master_df.shape[0]}')
            master_df.drop_duplicates(keep='first', inplace=True)
            shodan_logger.info(f'After duplicates are dropped are: {master_df.shape[0]}')

            master_df.to_csv(shodan_hosts_csv, index=False)

            shodan_logger.info(f'Code took {((time.time() - start_time) / 60):.3f} minutes to execute.')
            shodan_logger.info(f'---------------------------------------------------------------------------------')
            shodan_logger.info(f'\n')
        except Exception as e:
            shodan_logger.error(f'Error for domain_hostname_aggregator function is: {e}')


if __name__ == '__main__':
    # Insert API here
    api = ''
    ShodanSearchEngine(api)
