"""
CS 493 Cloud Computing
Portfolio Project
Genevieve Will
willge@oregonstate.edu
"""
from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack
import requests
from functools import wraps
import json
from urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
import json
from os import environ as env
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from urllib.parse import urlencode, quote_plus
import constants
