import pkce
import webbrowser
import requests
from flask import Flask, request
import threading
import yaml
import os
from xero_python.accounting import AccountingApi, ContactPerson, Contact, Contacts, BankTransactions, BankTransaction
from xero_python.api_client import ApiClient, serialize
from xero_python.api_client.configuration import Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.exceptions import AccountingBadRequestException
from xero_python.identity import IdentityApi
from xero_python.utils import getvalue
from utils import jsonify, serialize_model
import jwt
import datetime

# from xero_python import Xero
#from xero_python.api_client.oauth2 import OAuth2Credentials

access_token_file_path = 'access_token.yaml'
client_id = '317AA8E3CD974DAF8E193D4F0B54A4AC' # replace with your client ID
redirect_uri = 'http://localhost:8000/callback'
authorization_code = None
code_verifier = pkce.generate_code_verifier(length=128)




def start_app():
    app = Flask(__name__)
    shutdown_event = threading.Event()

    @app.route('/callback')
    def callback():
        global authorization_code
        authorization_code = request.args.get('code')
        # Store the authorization code securely for further processing

        # Perform the token exchange and subsequent API requests here

        shutdown_event.set()  # Set the event to stop the Flask server
        return 'Authorization code received: ' + authorization_code + '\n You can now close this page'

    @app.route('/shutdown', methods=['POST'])
    def shutdown():
        shutdown_func = request.environ.get('werkzeug.server.shutdown')
        if shutdown_func:
            shutdown_func()
        return 'Flask server shutting down...'

    app.run(port=8000)


def create_challenge():

    # Generate the PKCE code_verifier and code_challenge
    
    code_challenge = pkce.get_code_challenge(code_verifier)



    scope = 'offline_access accounting.transactions accounting.transactions.read'

    auth_url = ('https://login.xero.com/identity/connect/authorize?' +
                'response_type=code' +
                '&client_id=' + client_id +
                '&redirect_uri=' + redirect_uri +
                '&scope=' + scope +
                '&code_challenge=' + code_challenge +
                '&code_challenge_method=S256')

    # Open the authorization URL in a web browser
    webbrowser.open(auth_url)

    # Wait for the authorization code to be received
    while authorization_code is None:
        pass

    # Stop the Flask server after receiving the authorization code
    if server_thread.is_alive():
        # Request the Flask server to shut down gracefully
        response = requests.post('http://localhost:8000/shutdown')
        print(response.text)


def get_acccess_token():


    # Perform the token exchange using the authorization code and PKCE code_verifier
    exchange_url = 'https://identity.xero.com/connect/token'
    response = requests.post(exchange_url,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            data={
                                'grant_type': 'authorization_code',
                                'client_id': client_id,
                                'code': authorization_code,
                                'redirect_uri': redirect_uri,
                                'code_verifier': code_verifier
                            })

    # Process the response (access token, refresh token, etc.)
    response_json = response.json()

    access_token = response_json['access_token']
    refresh_token = response_json['refresh_token']

    return access_token, refresh_token

def get_tenant_id():

    url = 'https://api.xero.com/connections'
    response = requests.get(url,
            headers={
                'Authorization' : 'Bearer '+access_token,
                'Content-Type' : 'application/json'
            })
    conn_json = response.json()
    tenantId = ""
    for t in conn_json:
        if 'tenantId' in t:
            tenantId = t['tenantId']

    return tenantId


def check_token_expiration(access_token ):
    # Decode the JWT and extract the expiration time
    try:
        decoded_token = jwt.decode(access_token, options={"verify_signature": False},  algorithms=['HS256'])
        expiration_time = decoded_token['exp']
        
        # Convert the expiration time to a datetime object
        expiration_datetime = datetime.datetime.fromtimestamp(expiration_time)
        
        # Get the current time
        current_time = datetime.datetime.now()
        
        # Check if the token has expired
        token_expired = current_time >= expiration_datetime
        
        if token_expired:
            print('Access token has expired.')
            return True
        else:
            
            print('Access token is still valid.')
            return False
        
    except jwt.exceptions.DecodeError:
        print('Invalid access token.')
        return True



#check if the session is active
# Read the session token from the YAML file

access_token = None
tenant_id = None

if os.path.exists(access_token_file_path):

    with open(access_token_file_path, 'r') as file:
        data = yaml.safe_load(file)
        access_token = data.get('access_token')

    # Use the session_token as needed
    print('Session token:', access_token)


if access_token:

    if not check_token_expiration(access_token):

        tenant_id = get_tenant_id()

    
if not tenant_id:

    # Start the Flask server in a separate thread
    server_thread = threading.Thread(target=start_app)
    server_thread.start()
    create_challenge()
    access_token, refresh_token = get_acccess_token()
    tenant_id = get_tenant_id()

    # Write the session token to a YAML file
    data = {'access_token': access_token}

    with open(access_token_file_path, 'w') as file:
        yaml.dump(data, file)




api_url = 'https://api.xero.com/api.xro/2.0/BankTransactions'

headers = {
     'Authorization': 'Bearer ' + access_token,
    'Xero-tenant-id': tenant_id,
    'Accept' : 'application/json'

}

response = requests.get(api_url, headers=headers)



invoices_json = response.json()

invoices = response.json().get('Invoices', [])

print('Token exchange response:', response.json())
