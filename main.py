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
import starship


app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()

app.register_blueprint(starship.bp)

# Update the values of the following 3 variables
CLIENT_ID = ''
CLIENT_SECRET = ''
DOMAIN = '493-willge.us.auth0.com'
LOCAL_DOMAIN = 'localhost:8080'

ALGORITHMS = ["RS256"]
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://493-willge.us.auth0.com/.well-known/openid-configuration',
)

@app.route("/")
def home():
    return render_template(
        "index.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect('/loggedin')

@app.route("/loggedin", methods = ['GET'])
def loggedin():
    jwt = session["user"]
    userinfo = jwt['userinfo']
    query = client.query(kind=constants.crew)
    results = list(query.fetch())
    for e in results:
        if e['crew_num'] == userinfo['sub']:
            crew_num = e.key.id
            return render_template("login.html", jwt=jwt, userinfo=userinfo, crew_num=crew_num)
    new_crew = datastore.entity.Entity(key=client.key(constants.crew))
    new_crew.update({"crew_num": userinfo['sub'], "name": userinfo['nickname'], 'posts': None})
    client.put(new_crew)
    crew_key = client.key(constants.posts, new_crew.key.id)
    crew_num = client.get(key=crew_key)
    return render_template("login.html", jwt=jwt, userinfo=userinfo, crew_num=crew_num)

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response
# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)
        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

@app.route("/crew", methods=["GET"])
def crew():
    if request.method == 'GET':
        query = client.query(kind=constants.crew)
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
        output = {"crew": results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output), 201
    else:
        return (json.dumps({"Error":"Method not recognized"}), 405)

@app.route("/crew/<id>", methods=["PATCH", "DELETE"])
def patch_crew(id):
    if request.method == 'PATCH':
        crew_key = client.key(constants.crew, int(id))
        crew = client.get(key=crew_key)
        if crew_key == None or crew == None:
            return (json.dumps({"Error": "No Crew Member with this crew_id exists"}), 404)
        content = request.get_json()
        if "id" in content:
            return (json.dumps({"Error":"Cannot change crew id"}), 400)   
        if "name" in content:
            if not isinstance(content["name"], str):
                return (json.dumps({"Error": "One or more attributes are not correct input type"}), 400)
            else:
                query = client.query(kind=constants.crew)
                results = list(query.fetch())
                for e in results:
                    if e["name"] == content["name"]:
                        return (json.dumps({"Error": "Name of crew must be unique"}), 403)
                crew.update({'name': content['name']})
                client.put(crew)

        if "posts" in content:
            crew.update({"posts": content["posts"]})
            client.put(crew)
        res = make_response(json.dumps(crew))
        res.mimetype = 'application/json'
        res.status_code = 200
        return res
    elif request.method == 'DELETE':
        crew_key = client.key(constants.crew, int(id))
        crew = client.get(key=crew_key)
        if crew_key == None or crew == None:
            return (json.dumps({"Error": "No crew with this crew_id exists"}), 404)
        if not crew["posts"]:
            # Check if crew member has been assigned any posts
            client.delete(crew)
        else:
            # If Crew Member has a posting, delete crew from post
            post_key = client.key(constants.posts, int(crew["post"]["id"]))
            post = client.get(key=post_key)
            post["crew"] = None
            client.put(post)
            client.delete(crew)
        return ('', 204)
    else:
        return (json.dumps({"Error":"Method not recognized"}), 405)


@app.route('/posts', methods=['POST','GET'])
def posts_get_post():
    if request.method == 'POST':
        content = request.get_json()
        if 'title' in content and 'rank' in content and 'duties' in content:
            new_post = datastore.entity.Entity(key=client.key(constants.posts))
            new_post.update({"title": content['title'], "rank": content["rank"], "duties": content["duties"], 'crew': None, 'ship': None})
            client.put(new_post)
            post_key = client.key(constants.posts, new_post.key.id)
            post = client.get(key=post_key)
            post["id"] = new_post.key.id
            post["self"] = str(request.host_url) + 'posts/' + str(new_post.key.id)
            return json.dumps(post), 201
        else:
            return json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400
    elif request.method == 'GET':
        query = client.query(kind=constants.posts)
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
            e['self'] = str(request.host_url) + 'posts/' + str(e.key.id)
        output = {"posts": results}
        if next_url:
            output["next"] = next_url
        return (json.dumps(output), 200) 
    else:
        return (json.dumps({"Error":"Method not recognized"}), 405)

@app.route('/posts/<id>', methods=['GET','PUT', 'PATCH', 'DELETE'])
def posts_put_delete(id):
    post_key = client.key(constants.posts, int(id))
    post = client.get(key=post_key)
    if request.method == 'GET':
        if post_key == None or post == None:
            return json.dumps({"Error": "No post with this post_id exists"}), 404
        else:
            if not post['crew']:
                post["id"] = post.key.id
                post["self"] = str(request.host_url) + 'posts/' + str(post.key.id)
                return json.dumps(post), 200
            else:
                try:
                    payload = verify_jwt(request)
                    query = client.query(kind=constants.crew)
                    crew_sub = payload['sub']
                    query.add_filter('crew_num', '=', crew_sub)
                    post_list = list(query.fetch())
                    print(post['crew']['id'])
                    print (post_list[0].key.id)
                    if int(post['crew']['id']) == int(post_list[0].key.id):
                        post["id"] = post.key.id
                        post["self"] = str(request.host_url) + 'posts/' + str(post.key.id)
                        return json.dumps(post), 200
                    else:
                        return (json.dumps({'Error': 'Wrong crew member for this post'}), 403)
                except AuthError:
                    return (json.dumps({'Error': 'Missing or invalid JWT'}), 401)

    elif request.method == 'PUT':
        post_key = client.key(constants.posts, int(id))
        post = client.get(key=post_key)
        if post_key == None or post == None:
            return (json.dumps({"Error": "No post with this post_id exists"}), 404)
        content = request.get_json()
        if not post['crew']:
            post.update({"title": content["title"], "rank": content["rank"],
            "duties": content["duties"]})
            client.put(post)
            return ('',200)
        else:
            try:
                payload = verify_jwt(request)
                query = client.query(kind=constants.crew)
                crew_sub = payload['sub']
                query.add_filter('crew_num', '=', crew_sub)
                post_list = list(query.fetch())
                if int(post['crew']['id']) == (post_list[0].key.id):
                    post.update({"title": content["title"], "rank": content["rank"],
                    "duties": content["duties"]})
                    client.put(post)
                    res = make_response(json.dumps(post))
                    res.mimetype = 'application/json'
                    res.status_code = 200
                    return res
                else:
                    return (json.dumps({'Error': 'This crew member is not assigned to this post'}), 403)
            except AuthError:
                return (json.dumps({'Error': 'Missing or invalid JWT'}), 401)

    elif request.method == 'PATCH':
        post_key = client.key(constants.posts, int(id))
        post = client.get(key=post_key)
        if post_key == None or post == None:
            return (json.dumps({"Error": "No post with this post_id exists"}), 404)
        try:
            if request.headers['content-type'] != 'application/json':
                return (json.dumps({"Error": "The request must be JSON"}), 415)
        except KeyError:
            return (json.dumps({"Error": "The request must be JSON"}), 415)
        if 'application/json' not in request.accept_mimetypes:
            return json.dumps({"Error":"The response must be JSON"}), 406
        content = request.get_json()
        if "id" in content:
            return (json.dumps({"Error":"Cannot change post id"}), 400)
        if not post['crew']:  
            if "title" in content:
                post.update({'title': content['title']})
                client.put(post)
            if "rank" in content:
                post.update({"rank": content["rank"]})
                client.put(post)
            if "duties" in content:
                post.update({"duties": content["duties"]})
                client.put(post)
            res = make_response(json.dumps(post))
            res.mimetype = 'application/json'
            res.status_code = 200
            return res
        else:
            try:
                payload = verify_jwt(request)
                query = client.query(kind=constants.crew)
                crew_sub = payload['sub']
                query.add_filter('crew_num', '=', crew_sub)
                post_list = list(query.fetch())
                if int(post['crew']['id']) == (post_list[0].key.id):
                    if "title" in content:
                        post.update({'title': content['title']})
                        client.put(post)
                    if "rank" in content:
                        post.update({"rank": content["rank"]})
                        client.put(post)
                    if "duties" in content:
                        post.update({"duties": content["duties"]})
                        client.put(post)
                    res = make_response(json.dumps(post))
                    res.mimetype = 'application/json'
                    res.status_code = 200
                    return res
                else:
                    return (json.dumps({'Error': 'This crew member is not assigned to this post'}), 403)
            except AuthError:
                return (json.dumps({'Error': 'Missing or invalid JWT'}), 401)

    elif request.method == 'DELETE':
        if not post:
            return json.dumps({"Error": "No post with this post_id exists"}), 404
        if not post["ship"] and not post['crew']:
            client.delete(post)
            return('', 204)
        if post['crew']:
            try:
                payload = verify_jwt(request)
                query = client.query(kind=constants.crew)
                crew_sub = payload['sub']
                query.add_filter('crew_num', '=', crew_sub)
                post_list = list(query.fetch())
                crew_key = client.key(constants.crew, int(post_list[0].key.id))
                crew = client.get(key=crew_key)
                if int(post['crew']['id']) == int(post_list[0].key.id):
                    crew['posts'] = None
                    client.put(crew)
                else:
                    return (json.dumps({'Error': 'This crew member is not assigned to this post'}), 403)
            except AuthError:
                return (json.dumps({'Error': 'Missing or invalid JWT'}), 401)     
        if post['ship']:
            starship_key = client.key(constants.starships, int(post["ship"]["id"]))
            starship = client.get(key=starship_key)
            for assigned in starship["posts"]:
                if assigned["id"] == str(post.key.id):
                    starship["posts"].remove(assigned)
                    client.put(starship)
                    break
        client.delete(post)
        return('', 204)
    else:
        return (json.dumps({"Error":"Method not recognized"}), 405)



@app.route('/posts/<post_id>/crew/<crew_id>', methods=['PUT'])
def add_crew(post_id, crew_id):
    post_key = client.key(constants.posts, int(post_id))
    crew_key = client.key(constants.crew, int(crew_id))
    post = client.get(key=post_key)
    crew = client.get(key=crew_key)
    query = client.query(kind=constants.posts)
    query.key_filter(post_key, '=')
    post_result = list(query.fetch())
    query = client.query(kind=constants.crew)
    query.key_filter(crew_key, '=')
    crew_result = list(query.fetch())

    if request.method == 'PUT':
        # Assign a crew member to a post
        if not crew_result or not post_result:
            return json.dumps({"Error": "The specified post and/or crew member does not exist"}), 404
        elif crew_result or post_result:
            post = post_result[0]
            crew = crew_result[0]
            if post.get('crew') != None:
                return json.dumps({"Error": "The post is already assigned to another crew member"}), 403
            else:
                crew_link = request.host_url + 'crew/' + str(crew_id)
                post_link = request.host_url + 'posts/' + str(post_id)
                crew_obj = {"id": str(crew_id), "name": crew.get("name"), 'self': crew_link}
                post.update(crew=crew_obj)
                post_obj = ({"id": str(post_id), "title": post.get("title"), "rank": post.get("rank"), 'self': post_link})
                crew['posts'] = post_obj
                client.put(post)
                client.put(crew)
                return '', 204
    else:
        return (json.dumps({"Error":"Method not recognized"}), 405)



@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload    
        
# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    jwt = jsonify(r)
    return jwt

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
