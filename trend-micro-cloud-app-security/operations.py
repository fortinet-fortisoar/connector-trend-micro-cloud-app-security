""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json

import requests
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger('trend-micro-cloud-app-security')


def make_api_call(method="GET", endpoint="", config=None, params=None, data=None, json_data=None, endpoint_flag=True):
    try:
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            'Authorization': f'Bearer {config.get("token")}'
        }
        server_url = config.get('server_url')
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://" + server_url
        url = server_url + '/v1/' + endpoint if endpoint_flag else endpoint
        response = requests.request(method=method, url=url,
                                    headers=headers, data=data, json=json_data, params=params,
                                    verify=config.get('verify_ssl'))
        if response.ok:
            return response.json()
        else:
            if response.text != "":
                err_resp = response.json()
                failure_msg = err_resp['msg']
                error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                     failure_msg if failure_msg else '')
            else:
                error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
            logger.error(error_msg)
            raise ConnectorError(error_msg)
    except requests.exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except requests.exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except requests.exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except requests.exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as err:
        raise ConnectorError(str(err))


def build_payload(params):
    return {k: MAPPING.get(v, v) for k, v in params.items() if v is not None and v != ''}


def fetch_remaining_pages(response, key):
    result = response
    while response.get('next_link'):
        response = make_api_call(response.get('next_link'), endpoint_flag=False)
        result[key].extend(response[key])
    return result


def get_security_logs(config, params):
    get_all_pages = params.pop('get_all_pages')
    params = build_payload(params)
    endpoint = 'siem/security_events'
    response = make_api_call(endpoint=endpoint, params=params, config=config)
    return fetch_remaining_pages(response, 'security_events') if response.get(
        'next_link') and get_all_pages else response


def get_virtual_analyzer_report(config, params):
    endpoint = 'siem/security_events/va_analysis_report'
    return make_api_call(endpoint=endpoint, params=params, config=config)


def get_quarantine_events(config, params):
    get_all_pages = params.pop('get_all_pages')
    params = build_payload(params)
    endpoint = 'siem/quarantine_events'
    response = make_api_call(endpoint=endpoint, params=params, config=config)
    return fetch_remaining_pages(response, 'quarantine_events') if response.get(
        'next_link') and get_all_pages else response


def get_email(config, params):
    get_all_pages = params.pop('get_all_pages')
    params = build_payload(params)
    endpoint = 'sweeping/mails'
    response = make_api_call(endpoint=endpoint, params=params, config=config)
    return fetch_remaining_pages(response, 'value') if response.get('next_link') and get_all_pages else response


def take_action_on_user(config, params):
    params = build_payload(params)
    endpoint = 'mitigation/accounts'
    return make_api_call(method="POST", endpoint=endpoint, data=json.dumps([params]), config=config)


def take_action_on_email(config, params):
    params = build_payload(params)
    endpoint = 'mitigation/mails'
    return make_api_call(method="POST", endpoint=endpoint, data=json.dumps([params]), config=config)


def get_user_action_result(config, params):
    get_all_pages = params.pop('get_all_pages')
    params = build_payload(params)
    endpoint = 'mitigation/accounts'
    response = make_api_call(endpoint=endpoint, params=params, config=config)
    return fetch_remaining_pages(response, 'actions') if response.get('next_link') and get_all_pages else response


def get_email_action_result(config, params):
    get_all_pages = params.pop('get_all_pages')
    params = build_payload(params)
    endpoint = 'mitigation/mails'
    response = make_api_call(endpoint=endpoint, params=params, config=config)
    return fetch_remaining_pages(response, 'actions') if response.get('next_link') and get_all_pages else response


def get_blocked_list(config, params):
    endpoint = 'remediation/mails'
    return make_api_call(endpoint=endpoint, config=config)


def update_blocked_list(config, params):
    params = build_payload(params)
    endpoint = 'remediation/mails'
    rules_list = ['senders', 'urls', 'filehashes', 'file256hashes']
    rules = {}
    for x in rules_list:
        if params.get(x):
            rules[x] = [x.strip() for x in str(params.pop(x)).split(",")]
    params['rules'] = rules
    return make_api_call(method="POST", endpoint=endpoint, data=json.dumps(params), config=config)


def _check_health(config):
    try:
        params = {}
        get_blocked_list(config, params)
        return True
    except Exception as e:
        logger.error("Invalid Credentials: %s" % str(e))
        raise ConnectorError("Invalid Credentials")


operations = {
    'get_security_logs': get_security_logs,
    'get_virtual_analyzer_report': get_virtual_analyzer_report,
    'get_quarantine_events': get_quarantine_events,
    'get_email': get_email,
    'take_action_on_user': take_action_on_user,
    'take_action_on_email': take_action_on_email,
    'get_user_action_result': get_user_action_result,
    'get_email_action_result': get_email_action_result,
    'get_blocked_list': get_blocked_list,
    'update_blocked_list': update_blocked_list
}
