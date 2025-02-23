import sys
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtWebEngineWidgets import QWebEngineView

import os
from functools import wraps
from io import BytesIO
from logging.config import dictConfig

import dateutil

from flask import Flask, url_for, render_template, session, redirect, json, send_file
from flask_oauthlib.contrib.client import OAuth, OAuth2Application
from flask_session import Session
from xero_python.accounting import AccountingApi, ContactPerson, Contact, Contacts, BankTransactions, BankTransaction
from xero_python.api_client import ApiClient, serialize
from xero_python.api_client.configuration import Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.exceptions import AccountingBadRequestException
from xero_python.identity import IdentityApi
from xero_python.utils import getvalue


import logging_settings
from utils import jsonify, serialize_model

import pdb

dictConfig(logging_settings.default_settings)

# # configure main flask application
# app = Flask(__name__)
# app.config.from_object("default_settings")
# app.config.from_pyfile("config.py", silent=True)

# #GPT advice
# #app.config['SESSION_TYPE'] = 'filesystem'

# if app.config["ENV"] != "production":
#     # allow oauth2 loop to run over http (used for local testing only)
#     os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# # configure persistent session cache
# Session(app)

# configure flask-oauthlib application
# TODO fetch config from https://identity.xero.com/.well-known/openid-configuration #1
oauth = OAuth(app)
xero = oauth.remote_app(
    name="xero",
    version="2",
    client_id=app.config["CLIENT_ID"],
    client_secret=app.config["CLIENT_SECRET"],
    endpoint_url="https://api.xero.com/",
    authorization_url="https://login.xero.com/identity/connect/authorize",
    access_token_url="https://identity.xero.com/connect/token",
    refresh_token_url="https://identity.xero.com/connect/token",
    scope="offline_access openid profile email accounting.transactions "
    "accounting.reports.read accounting.journals.read accounting.settings "
    "accounting.contacts accounting.attachments assets projects",
)  # type: OAuth2Application


# configure xero-python sdk client
api_client = ApiClient(
    Configuration(
        debug=app.config["DEBUG"],
        oauth2_token=OAuth2Token(
            client_id=app.config["CLIENT_ID"], client_secret=app.config["CLIENT_SECRET"]
        ),
    ),
    pool_threads=1,
)








class AuthorizationWindow(QMainWindow):
    def __init__(self, url):
        super().__init__()
        self.setWindowTitle("Authorization")
        self.setGeometry(100, 100, 800, 600)

        self.web_view = QWebEngineView(self)
        self.setCentralWidget(self.web_view)

        self.web_view.load(url)

        self.web_view.urlChanged.connect(self.handle_url_changed)

    def handle_url_changed(self, url):
        # Check if the authorization is complete
        if "authorization_successful" in url.toString():
            # Extract the required authorization details from the URL
            # Example: http://localhost/?authorization_successful&token=123456789
            # You can parse the URL to extract the necessary information
            # For example, you can use regular expressions or string manipulation

            # Close the authorization window
            self.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    authorization_url = "https://example.com/authorize"  # Replace with your authorization URL
    window = AuthorizationWindow(authorization_url)
    window.show()

    sys.exit(app.exec_())
