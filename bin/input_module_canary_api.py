
# encoding = utf-8

import sys
import time
import json

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    pass

def collect_events(helper, ew):
    domain = helper.get_global_setting('canary_domain')
    api_key = helper.get_global_setting("api_key")
    incident_limit = 20

    #Admin can use XXXXXXX.canary.tools or simply XXXXXXX
    if not domain.endswith('.canary.tools'):
        domain += '.canary.tools'

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
        helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(e))
        sys.exit()

    if response.status_code == 200:
        #Successfull Connection
        helper.log_info("Successfully connected to Canary.tools API")

        #Get current time for testing purposes.
        current_time = time.time()

        #Collect All incidents from Canary Tools
        url_allIncidents    = "https://{}/api/v1/incidents/all?tz=UTC&limit={}".format(domain,incident_limit)
        if helper.get_check_point('last_updated_id'):
            url_allIncidents += '&incidents_since={}'.format(helper.get_check_point('last_updated_id'))
            # helper.log_info("last_updated_id URL is {}".format(url_allIncidents))

        #Collect All Registered Devices from Canary Tools
        url_regDevices = "https://{}/api/v1/devices/all?tz=UTC".format(domain)

        #Collect All Canary Tokens from Canary Tools
        url_canarytokens_fetch = "https://{}/api/v1/canarytokens/fetch".format(domain)

        #Issue a new response to the Registered DevicesAPI
        response_regDevices = helper.send_http_request(url_regDevices, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

        #Issue a new response to the Canary Tokens API
        response_canarytokens_fetch = helper.send_http_request(url_canarytokens_fetch, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

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
        #Issue a new response to the All Incidents API
        response_allIncidents = helper.send_http_request(url_allIncidents, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

        #Try to connect to the url for All Incidents
        try:
            response_allIncidents
        #Throw an exception if it fails
        except Exception as e:
            helper.log_error("Error occured with canary.tools API call to retrieve all Incidents. Error Message: {}".format(e))
            sys.exit()

        #Set the most recent updated_id to the last seen incident updated_id, or the epoch
        last_updated_id = helper.get_check_point('last_updated_id')
        if not last_updated_id:
            last_updated_id = 0

        while response_allIncidents.status_code == 200:
            #If we receive a 200 response from the all incidents API
            #Output the results to json
            data = response_allIncidents.json()

            try:
                if last_updated_id < data['max_updated_id']:
                    last_updated_id = data['max_updated_id']
            except:
                #max_updated_id is only present on queries with incidents
                pass

            if len(data['incidents']) >0:
                for a in data['incidents']:
                    #Add current time of server to timestamp
                    a['_time'] = current_time
                    #Convert data to a string
                    data_dump = json.dumps(a)
                    #Write the event to the destination index
                    event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:incidents")
                    ew.write_event(event)
            else:
                #If no incidents have been logged
                #Add current time of server to timestamp
                helper.log_info("No incidents have been logged. Successful connection to canaryapi")

            if not data['cursor']['next_link']:
                break

            response_allIncidents = helper.send_http_request(data['cursor']['next_link'], method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)
        #If the resposne code from querying the Incidents is not 200
        else:
            helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response_allIncidents.json()))

        if last_updated_id:
            helper.save_check_point('last_updated_id', last_updated_id)
            helper.log_debug("Setting last_updated_id checkpoint to {}".format(last_updated_id))

        #If we receive a 200 response from the registered devices API
        if response_regDevices.status_code == 200:
            #Output the results to json
            data = response_regDevices.json()
            if len(data['devices']) >0:
                for a in data['devices']:
                    #Only create a device event for new or changed devices
                    check_point_key = 'device:'+a['id']
                    saved_data = helper.get_check_point(check_point_key)
                    if not saved_data:
                        saved_data = {}

                    monitor_fields = ['name', 'description', 'ip_address', 'live', 'version']
                    fields_changed = False
                    for field in monitor_fields:
                        if a.get(field, None) != saved_data.get(field, None):
                            fields_changed = True
                            break
                    if not fields_changed:
                        continue
                    helper.save_check_point(check_point_key, a)


                    #Add current time of server to timestamp
                    a['_time'] = current_time
                    #Convert data to a string
                    data_dump = json.dumps(a)
                    #Write the event to the destination index
                    event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:devices")
                    ew.write_event(event)
            else:
                #If no devices have been registered
                #Add current time of server to timestamp
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
                    #Only create a token event for new or changed tokens
                    check_point_key = 'token:'+a['node_id']
                    saved_data = helper.get_check_point(check_point_key)
                    if not saved_data:
                        saved_data = {}

                    monitor_fields = ['memo','enabled']
                    fields_changed = False
                    for field in monitor_fields:
                        if a.get(field, None) != saved_data.get(field, None):
                            fields_changed = True
                            break
                    if not fields_changed:
                        continue
                    helper.save_check_point(check_point_key, a)


                    #Add current time of server to timestamp
                    a['_time'] = current_time
                    #Convert data to a string
                    data_dump = json.dumps(a)
                    #Write the event to the destination index
                    event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:tokens")
                    ew.write_event(event)
            else:
                #If no tokens have been registered
                #Add current time of server to timestamp
                helper.log_info("No tokens have been regiestered. Successful connection to canaryapi")


        else:
            helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response_canarytokens_fetch.json()))


    else:
        helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response.json()))