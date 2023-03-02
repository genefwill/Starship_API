"""
CS 493 Cloud Computing
Portfolio Project
Genevieve Will
willge@oregonstate.edu
"""
from google.cloud import datastore
from flask import Flask, Blueprint, request, jsonify, _request_ctx_stack, make_response
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

client = datastore.Client()

bp = Blueprint('starships', __name__, url_prefix='/starships')

@bp.route('', methods=['POST', 'GET', 'DELETE'])
def starships_get_post():
    if request.method == 'POST':
        content = request.get_json()
        if "name" in content and "class" in content and "mission" in content:
            query = client.query(kind=constants.starships)
            results = list(query.fetch())
            for e in results:
                if e["name"] == content["name"]:
                    return (json.dumps({"Error": "Name of starship must be unique"}), 403)
            new_starship = datastore.entity.Entity(key=client.key(constants.starships))
            new_starship.update({"name": content["name"], "class": content["class"], "mission": content["mission"], 'posts': []})
            client.put(new_starship)
            starship_key = client.key(constants.starships, new_starship.key.id)
            starship = client.get(key=starship_key)     
            starship["id"] = new_starship.key.id
            starship["self"] = str(request.host_url) + 'starships/' + str(new_starship.key.id)
            return (json.dumps(starship), 201)
        else:
            return (json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400)
    elif request.method == 'GET':
        query = client.query(kind=constants.starships)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        b_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = b_iterator.pages
        results = list(next(pages))
        if b_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e['self'] = str(request.host_url) + 'starships/' + str(e.key.id)
        output = {"starships": results}
        if next_url:
            output["next"] = next_url
        return (json.dumps(output), 200) 
    else:
        return (json.dumps({"Error":"Method not recognized"}), 405)

@bp.route('/<id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def starships_get_patch_delete(id):
    if request.method == 'GET':  
        # Get starship with given id
        starship_key = client.key(constants.starships, int(id))
        starship = client.get(key=starship_key)
        if starship_key == None or starship == None:
            return (json.dumps({"Error": "No starship with this starship_id exists"}), 404)
        else:
            starship["id"] = starship.key.id
            starship["self"] = str(request.host_url) + 'starships/' + str(starship.key.id)
            return (json.dumps(starship), 200)
    elif request.method == 'PUT':
        starship_key = client.key(constants.starships, int(id))
        starship = client.get(key=starship_key)
        if request.headers['content-type'] != 'application/json':
            return (json.dumps({"Error": "The request must be JSON"}), 415)
        if 'application/json' not in request.accept_mimetypes:
            return json.dumps({"Error":"The response must be JSON"}), 406
        if starship_key == None or starship == None:
            return (json.dumps({"Error": "No starship with this starship_id exists"}), 404)
        content = request.get_json()
        if "id" in content:
            return (json.dumps({"Error":"Cannot change starship id"}), 400)
        if "name" in content and "class" in content and "mission" in content:
            query = client.query(kind=constants.starships)
            results = list(query.fetch())
            for e in results:
                if e["name"] == content["name"]:
                    return (json.dumps({"Error": "Name of starship must be unique"}), 403)
            starship.update({"name": content["name"], "class": content["class"], "mission": content["mission"]})
            client.put(starship)
            res = make_response(json.dumps(starship))
            res.mimetype = 'application/json'
            res.status_code = 200
            return res
        else:
            return (json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400)
    elif request.method == 'PATCH':
        starship_key = client.key(constants.starships, int(id))
        starship = client.get(key=starship_key)
        if starship_key == None or starship == None:
            return (json.dumps({"Error": "No starship with this starship_id exists"}), 404)
        if request.headers['content-type'] != 'application/json':
            return (json.dumps({"Error": "The request must be JSON"}), 415)
        if 'application/json' not in request.accept_mimetypes:
            return json.dumps({"Error":"The response must be JSON"}), 406
        if starship_key == None or starship == None:
            return (json.dumps({"Error": "No Starship with this starship_id exists"}), 404)
        content = request.get_json()
        if "id" in content:
            return (json.dumps({"Error":"Cannot change starship id"}), 400)   
        if "name" in content:
            if not isinstance(content["name"], str):
                return (json.dumps({"Error": "One or more attributes are not correct input type"}), 400)
            else:
                query = client.query(kind=constants.starships)
                results = list(query.fetch())
                for e in results:
                    if e["name"] == content["name"]:
                        return (json.dumps({"Error": "Name of starship must be unique"}), 403)
                starship.update({'name': content['name']})
                client.put(starship)
        if "class" in content:
            if not isinstance(content["class"], str):
                return (json.dumps({"Error": "One or more attributes are not correct input type"}), 400)
            else:
                starship.update({"class": content["class"]})
                client.put(starship)
        if "mission" in content:
            if not isinstance(content["mission"], str):
                return (json.dumps({"Error": "One or more attributes are not correct input type"}), 400)
            else:
                starship.update({"mission": content["mission"]})
                client.put(starship)
        res = make_response(json.dumps(starship))
        res.mimetype = 'application/json'
        res.status_code = 200
        return res
    elif request.method == 'DELETE':
        starship_key = client.key(constants.starships, int(id))
        starship = client.get(key=starship_key)
        if starship_key == None or starship == None:
            return (json.dumps({"Error": "No Starship with this starship_id exists"}), 404)
        else:
            client.delete(starship_key)
            if not starship["posts"]:
                # Check if there are any posts assigned to this starship
                client.delete(starship)
            else:
                # If Posts are assigned to this Starship, release those posts
                for assigned in starship["posts"]:
                    post_key = client.key(constants.posts, int(assigned["id"]))
                    post = client.get(key=post_key)
                    post["ship"] = None
                    client.put(post)
                client.delete(starship)
            return ('', 204)
    else:
        return (json.dumps({"Error":"Method not recognized"}), 405)

@bp.route('/<starship_id>/posts/<post_id>', methods=['PUT','DELETE'])
def add_del_posts(starship_id, post_id):
    post_key = client.key(constants.posts, int(post_id))
    starship_key = client.key(constants.starships, int(starship_id))
    post = client.get(key=post_key)
    starship = client.get(key=starship_key)
    query = client.query(kind=constants.posts)
    query.key_filter(post_key, '=')
    post_result = list(query.fetch())
    query = client.query(kind=constants.starships)
    query.key_filter(starship_key, '=')
    starship_result = list(query.fetch())

    if request.method == 'PUT':
        # Assign given post to given starship
        if not starship_result or not post_result:
            return json.dumps({"Error": "The specified starship and/or post does not exist"}), 404
        elif starship_result or post_result:
            post = post_result[0]
            starship = starship_result[0]
            if post.get('ship') != None:
                return json.dumps({"Error": "The post is already assigned to another starship"}), 403
            else:
                starship_link = request.host_url + 'starships/' + str(starship_id)
                post_link = request.host_url + 'posts/' + str(post_id)
                starship_obj = {"id": str(starship_id), "name": starship.get("name"), 'self': starship_link}
                post.update(ship=starship_obj)
                post_obj = ({"id": str(post_id), "title": post.get("title"), 'self': post_link})
                starship['posts'].append(post_obj)
                client.put(post)
                client.put(starship)
                return '', 204
    elif request.method == 'DELETE':
        if not starship_result or not post_result:
            return json.dumps({"Error": "The specified starship and/or post does not exist"}), 404
        else:
            post = post_result[0]
            starship = starship_result[0]
            for assigned in starship["posts"]:
                if assigned["id"] == str(post_id):
                    post['ship'] = None
                    starship["posts"].remove(assigned)
                    client.put(starship)
                    client.put(post)
                    break
                else:
                    return json.dumps({"Error": "The post is not assigned to this starship"}), 403
            return '', 204
    return (json.dumps({"Error":"Method not recognized"}), 405)

