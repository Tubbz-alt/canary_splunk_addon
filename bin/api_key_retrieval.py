def get_api_key(splunk_service):
    storage_passwords = splunk_service.storage_passwords
    realm = 'ta_canary_settings_realm'
    returned_credential = [k for k in storage_passwords if k.content.get('realm')==realm][0]
    usercreds = {'username':returned_credential.content.get('username'), 'password':returned_credential.content.get('clear_password')}
    api_key = usercreds['password']
    return api_key
