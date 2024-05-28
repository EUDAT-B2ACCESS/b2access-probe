#!/usr/bin/env python

import argparse
import sys

import signal
import json
from functools import wraps
from time import strftime, gmtime

import urllib3
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import requests
import subprocess
import datetime
from oauthlib.oauth2.rfc6749.errors import MissingTokenError
from requests.exceptions import ConnectionError, HTTPError
import os.path
import validators

TEST_SUFFIX = f"NAGIOS-{strftime('%Y%m%d-%H%M%S', gmtime())}"
VALUE_ORIG = f"http://www.{TEST_SUFFIX}.com/1"  # TODO this is ugly
VALUE_AFTER = f"http://www.{TEST_SUFFIX}.com/2"
TOKEN_URI = '/oauth2/token'


def handler(*args):
    print("UNKNOWN: Timeout reached, exiting.")
    sys.exit(3)


def exceptionHandler(message: str):
    def handleExceptions(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                ret = func(*args, **kwargs)
            except BaseException:
                print(message, sys.exc_info()[0])
                sys.exit(2)
            return ret
        return wrapper
    return handleExceptions


@exceptionHandler("CRITICAL: Error fetching OAuth 2.0 access token:")
def getAccessToken(param):
    """Fetch access token from B2ACCESS"""
    if param.verbose:
        print("\nFetching access token from B2ACCESS")
    """ Pre-req: Create a user 'argo' with password 'test' in group 'oauth-clients' and 'eudat:b2share' or any other """

    try:
        client = BackendApplicationClient(client_id=username)
        client.prepare_request_body(scope=['profile', 'email', 'GENERATE_USER_CERTIFICATE'])
        oauth = OAuth2Session(client=client)
        token = oauth.fetch_token(token_url=str(param.url) + TOKEN_URI, verify=False, client_id=str(param.username),
                                  client_secret=str(param.password),
                                  scope=['USER_PROFILE', 'GENERATE_USER_CERTIFICATE'])
        j = json.dumps(token, indent=4)
        k = json.loads(j)
        if param.verbose:
            print("Access token: " + k['access_token'])

        getTokenInfo(str(param.url) + '/oauth2/tokeninfo', str(k['access_token']), param.verbose)
        getUserInfo(str(param.url) + '/oauth2/userinfo', str(k['access_token']), param.verbose)
    except ConnectionError as e:
        print("CRITICAL: Invalid Unity URL: {0}".format(e))
        sys.exit(2)
    except MissingTokenError as e:
        print("CRITICAL: Invalid client Id and/or secret: {0}".format(e.description))
        sys.exit(2)
    except TypeError as e:
        print(e)
        sys.exit(2)


@exceptionHandler("CRITICAL: Error retrieving access token information:")
def getTokenInfo(url, token, verbose):
    """ Fetch access token details """
    try:
        if verbose:
            print(f"\nFetching access token information from URL: {url}")

        entity = requests.get(url, verify=False, headers={'Authorization': 'Bearer ' + token})
        j = entity.json()
        expire = datetime.datetime.fromtimestamp(int(j['exp'])).strftime('%Y-%m-%d %H:%M:%S')
        if verbose:
            print(f"Expires on: {expire}\nDetailed token info: {entity.text}")
    except KeyError as e:
        print("WARNING: Invalid key(s): {0}".format(e))
        sys.exit(1)
    except ValueError as e:
        print("CRITICAL: Invalid access token: {0}".format(e))
        sys.exit(2)
    except ConnectionError as e:
        print("CRITICAL: Invalid token endpoint URL: {0}".format(e))
        sys.exit(2)


@exceptionHandler("CRITICAL: Error retrieving user information:")
def getUserInfo(url, token, verbose):
    """ Fetch user information using access token """
    try:
        if parser_args.verbose:
            print(f"\nFetching user information based on access token, endpoint URL: {url}")
        entity = requests.get(url, verify=False, headers={'Authorization': 'Bearer ' + token})
        j = entity.json()
        if parser_args.verbose:
            print(
                f"Subject: {j['sub']}\nPersistent Id: {j['unity:persistent']}\n\
                Detailed user information: {entity.text}")
    except KeyError as e:
        print("WARNING: Invalid key(s): {0}".format(e))
        sys.exit(1)
    except ValueError as e:
        print("CRITICAL: Invalid access token: {0}".format(e))
        sys.exit(2)
    except ConnectionError as e:
        print("CRITICAL: Invalid UserInfo endpoint URL: {0}".format(e))
        sys.exit(2)


@exceptionHandler("CRITICAL: Error retrieving user information with the username/password:")
def getInfoUsernamePassword(param):
    """ Query user information with username and password """

    url = param.url + "/rest-admin/v1/resolve/userName/" + str(param.username)

    if param.verbose:
        print(f"\nQuery with username and password, endpoint URL: {url}")

    try:
        uname = param.username
        pwd = param.password
        entity = requests.get(str(url), verify=False, auth=(uname, pwd))
        if entity.status_code == 403:
            print("CRITICAL: Error retrieving the user information with username {0}: invalid username/password".format(
                uname))
            sys.exit(2)
        j = entity.json()
        if param.verbose:
            print(f"\nCredential requirement: {j['credentialInfo']['credentialRequirementId']}\n\
                Entity Id: {str(j['id'])}\n\
                Username: {j['identities'][0]['value']}\n\
                Detailed user information: {entity.text}")

    except ConnectionError as e:
        print("CRITICAL: Invalid Unity endpoint URL: {0}".format(e))
        sys.exit(2)
    except HTTPError as e:
        print(e)
        sys.exit(2)
    except KeyError as e:
        print("CRITICAL: Invalid key(s): {0}".format(e))
        sys.exit(2)


@exceptionHandler("CRITICAL: Error retrieving user information by X509 certificate:")
def getInfoCert(param):
    """ Query user information with X509 Certificate Authentication """
    try:
        cert_txt = subprocess.check_output(["openssl", "x509", "-subject", "-noout", "-in", param.certificate])
        sub = str(cert_txt).replace("subject= ", "")
        dn = getLdapName(sub)
        """ url = param.url+"/rest-admin/v1/resolve/x500Name/CN=Ahmed Shiraz Memon,OU=IAS-JSC,OU=Forschungszentrum Juelich GmbH,O=GridGermany,C=DE" """
        url = f"{param.url}/rest-admin/v1/resolve/x500Name/{dn}"

        print(f"url: {url}")

        if param.verbose:
            print(f"\nQuery user information with X509 Certificate Authentication, endpoint URL: {url}")

        entity = requests.get(str(url), verify=False, cert=(str(param.certificate), str(param.key)))

        if (entity.status_code == 400) or (entity.status_code == 403):
            print("CRITICAL: Error retrieving the user information with X500Name {0}: invalid certificate".format(dn))
            sys.exit(2)

        j = entity.json()

        if param.verbose:
            print(f"Credential requirement: {j['credentialInfo']['credentialRequirementId']}")
            """print "Entity Id: "+str(j['entityId'])"""
            print(f"Entity Id: {str(j['entityInformation']['entityId'])}")
            print(f"X500Name: {j['identities'][0]['value']}")
            print(f"Detailed user information: \n{json.dumps(j, indent=4)}")
    except HTTPError as e:
        print(e)
        sys.exit(2)
    except KeyError as e:
        print("CRITICAL: Invalid key(s): {0}".format(e))
        sys.exit(2)


def getLdapName(openssl_name):
    name = str(openssl_name)
    strs = name.split("/")
    strs.reverse()

    strs[0] = str(strs[0]).rstrip()
    strs.pop()

    # print(strs) why?
    str1 = ','.join(strs)
    return str1


if __name__ == '__main__':
    # disable ssl warnings and trust the unity server
    urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description='B2ACCESS login, query probe')

    # req = parser.add_argument_group('required arguments')

    subParsers = parser.add_subparsers()

    parser.add_argument('-u', '--url', action='store', dest='url', required=True,
                        help='baseuri of B2ACCESS-UNITY to test')
    parser.add_argument('-t', '--timeout', action='store', dest='timeout',
                        help='timeout')
    parser.add_argument('-v', '--version', action='store', dest='version',
                        help='version')
    parser.add_argument('-V', '--verbose', action='store_true', dest='verbose',
                        help='increase output verbosity', default=False)
    parser.add_argument('-d', '--debug', action='store_true', dest='debug',
                        help='debug mode')
    u_parser = subParsers.add_parser('1', help='Username/Password based authentication')
    u_parser.add_argument('-U', '--username', action='store', dest='username', required=True,
                          help='B2ACCESS user')
    u_parser.add_argument('-P', '--password', action='store', dest='password', required=True,
                          help='B2ACCESS password')
    u_parser.set_defaults(action='1')

    c_parser = subParsers.add_parser('2', help='X.509 Certificate based authentication')
    c_parser.add_argument('-C', '--cert', action='store', dest='certificate',
                          help='Path to public key certificate', required=True)
    c_parser.add_argument('-K', '--key', action='store', dest='key',
                          help='Path to private key', required=True)
    c_parser.set_defaults(action='2')

    parser_args = parser.parse_args()
    base_url = parser_args.url
    timeout = parser_args.timeout
    username = ""
    print(parser_args)

    if parser_args.action == "1":
        username = parser_args.username
        password = parser_args.password

    if parser_args.verbose:
        print("verbosity is turned ON")

    if parser_args.timeout and int(parser_args.timeout) > 0:
        print(f"Timeout: {timeout}")
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(int(parser_args.timeout))

    if parser_args.verbose:
        print(f"Starting B2ACCESS Probe...\n---------------------------\n\
            B2ACCESS url: {str(base_url)}")
        if parser_args.action == "1":
            print(f"B2ACCESS username: {username}")
        elif parser_args.action == "2":
            print(f"Public key: {parser_args.certificate}")
    try:
        if parser_args.action == "2":
            if not os.path.exists(parser_args.certificate):
                raise IOError(
                    "CRITICAL: Public key certificate file does not exist: {0}".format(parser_args.certificate))
            if not os.path.exists(parser_args.key):
                raise IOError("CRITICAL: Private key file does not exist: : {0}".format(parser_args.key))
        if not validators.url(parser_args.url):
            raise SyntaxError("CRITICAL: Invalid URL syntax {0}".format(parser_args.url))
    except IOError as e:
        print(e)
        sys.exit(2)
    except SyntaxError as e:
        print(e)
        sys.exit(2)
    except BaseException:
        print(sys.exc_info()[0])
        sys.exit(2)

    if parser_args.action == "1":
        getAccessToken(parser_args)
        getInfoUsernamePassword(parser_args)

    if parser_args.action == "2":
        getInfoCert(parser_args)

    if parser_args.verbose:
        if parser_args.action == "1":
            print("\nOK, User access token retrieval and login with username/password was successful")
        elif parser_args.action == "2":
            print("\nOK, User login with X.509 Certificate was successful")
    else:
        print("OK")
    sys.exit(0)
