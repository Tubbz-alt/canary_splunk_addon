
# encoding = utf-8

import sys
import time
import json

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    pass

def collect_events(helper, ew):
    domain = helper.get_global_setting('canary_domain')

    #Admin can use XXXXXXX.canary.tools or simply XXXXXXX
    if not domain.endswith('.canary.tools'):
        domain += '.canary.tools'

    api_key = helper.get_global_setting("api_key")
    incident_limit = 20

    #Check to see if proxy setting is configured
    proxy = helper.get_proxy()

    if proxy:
        use_proxy = True
    else:
        use_proxy = False

    #Set a custom useragent header for Splunk API so Canary.tools can measure the use of the product
    #Include the TA-canary version number
    try:
        version = [ i for i in helper.service.apps.list() if i.name == helper.app][0].content['version']
    except:
        version = 'N/A'
    headers = {'User-Agent': 'Splunk API Call ({})'.format(version),
               'X-Canary-Auth-Token': api_key}


    #Pass the domain and the api key to the url.
    url = "https://{}/api/v1/ping".format(domain)

    #Set the method of Get to the console
    method = "GET"
    #Try the first connection to see if it works.
    response = helper.send_http_request(url, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

    try:
        response
    except Exception as e:
        helper.log_error("Error occured with canary.tools Device poll API call. Error Message: {}".format(e))
        sys.exit()

    if response.status_code == 200:
        #Successfull Connection
        helper.log_info("Successfully connected to Canary.tools API")

        #Get current time for testing purposes.
        current_time = time.time()

        #Collect All unacknowledged incidents from Canary Tools
        url_unacknowledgedIncidents    = "https://{}/api/v1/incidents/unacknowledged?tz=UTC&limit={}".format(domain,incident_limit)

        url_cursorIncidents = "https://{}/api/v1/incidents/unacknowledged?tz=UTC&cursor=".format(domain)

        #Collect All Registered Devices from Canary Tools
        url_regDevices = "https://{}/api/v1/devices/all?tz=UTC".format(domain)

        #Collect All Canary Tokens from Canary Tools
        url_canarytokens_fetch = "https://{}/api/v1/canarytokens/fetch".format(domain)

        #Issue a new response to the Registered DevicesAPI
        response_regDevices = helper.send_http_request(url_regDevices, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

        #Issue a new response to the Canary Tokens API
        response_canarytokens_fetch = helper.send_http_request(url_canarytokens_fetch, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

        #Issue a new response to the All Incidents API
        response_unacknowledgedIncidents = helper.send_http_request(url_unacknowledgedIncidents, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

        #Try to connect to the url for All Incidents
        try:
            response_unacknowledgedIncidents
        #Throw an exception if it fails
        except Exception as e:
            helper.log_error("Error occured with canary.tools API call to retrieve all unacknowledged Incidents. Error Message: {}".format(e))
            sys.exit()
        #Set the most recent timestamp to the current time.
        most_recent_timestamp = current_time

        #Try to connect to the url for registered devices
        try:
            response_regDevices
        #Throw an exception if it fails
        except Exception as e:
            helper.log_error("Error occured with canary.tools API call to retrieve all registered devices. Error Message: {}".format(e))
            sys.exit()
        #Try to connect to the url for canary tokens
        try:
            response_canarytokens_fetch
        #Throw an exception if it fails
        except Exception as e:
            helper.log_error("Error occured with canary.tools API call to retrieve all canary tokens. Error Message: {}".format(e))
            sys.exit()

        #If we receive a 200 response from the registered devices API
        if response_regDevices.status_code == 200:
            #Output the results to json
            data = response_regDevices.json()
            if len(data['devices']) >0:
                for a in data['devices']:
                    #Add current time of server to timestamp
                    a['_time'] = current_time
                    #Convert data to a string
                    data_dump = json.dumps(a)
                    #Write the event to the destination index
                    event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:devices")
                    ew.write_event(event)
            else:
                #If no devices have been registered
                helper.log_info("No devices have been registered. Successful connection to canaryapi")

        #If the resposne code from querying the Registered devices is not 200
        else:
            helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response_regDevices.json()))

        #If we receive a 200 response from the canary tokens API
        if response_canarytokens_fetch.status_code == 200:
            #Output the results to json
            data = response_canarytokens_fetch.json()

            if len(data['tokens']) >0:
                for a in data['tokens']:
                    #Add current time of server to timestamp
                    a['_time'] = current_time
                    #Convert data to a string
                    data_dump = json.dumps(a)
                    #Write the event to the destination index
                    event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:tokens")
                    ew.write_event(event)
            else:
                #If no tokens have been registered
                helper.log_info("No tokens have been regiestered. Successful connection to canaryapi")


        else:
            helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response_canarytokens_fetch.json()))

        while response_unacknowledgedIncidents.status_code == 200:
            #If we receive a 200 response from the all incidents API
            #Output the results to json
            data = response_unacknowledgedIncidents.json()

            if len(data['incidents']) >0:
                for a in data['incidents']:
                    #Add current time of server to timestamp
                    a['_time'] = current_time
                    #Convert data to a string
                    data_dump = json.dumps(a)
                    #Write the event to the destination index
                    event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:incidents")
                    ew.write_event(event)
                    try:
                        created_timestamp = long(a['description']['created'])
                        if created_timestamp > most_recent_timestamp:
                            most_recent_timestamp = created_timestamp
                    except (KeyError, ValueError) as e:
                        helper.log_error("Error updating timestamp {}".format(e))

            else:
                #If no incidents have been logged
                helper.log_info("No incidents have been logged. Successful connection to canaryapi")

            if not data['cursor']['next_link']:
                break

            response_unacknowledgedIncidents = helper.send_http_request(data['cursor']['next_link'], method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)
        #If the resposne code from querying the Incidents is not 200
        else:
            helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response_unacknowledgedIncidents.json()))

    else:
        helper.log_error("Error occured with canary.tools device API call. Error Message: {}".format(response.json()))
