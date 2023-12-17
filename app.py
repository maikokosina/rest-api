#!venv/bin/python

import hashlib
import json
from flask import Flask, request, jsonify, abort, make_response
from flask_httpauth import HTTPBasicAuth
from pymongo import MongoClient

app = Flask(__name__)
auth = HTTPBasicAuth()

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.archive
users = db.users
pages = db.pages
access = db.access
files = db.files

users_cursor = users.find({ },{ "_id": 0, "avatar": 0})
users_list = list(users_cursor)

@auth.verify_password
def verify(username, password):
	if not (username and password):
		return False
	passmd5 = hashlib.md5(password.encode('utf-8')).hexdigest() 
	user_auth = users.find_one({"user_name": username, "password": passmd5.upper()},{ "_id": 0, "avatar": 0})
	if user_auth is None:
		abort(401)
	return username
	
@app.route('/rest-api/v1.0/<password>', methods=['GET'])
def get_pass(password):
	if users.find_one({"password": password}) is None:
		abort(401)
	for user in users.find({"password": password}):
		username = user['user_name']
		user_id = str(user['user_id'])
	message = 'Hi, ' + username + '. Your ID is ' + user_id
	return jsonify({'message': message})
	
@auth.error_handler
def unauthorized():
	return make_response(jsonify({'message': 'Unauthorized access'}), 401)
	
@app.errorhandler(400)
def bad_request(error):
	return make_response(jsonify({'error': 'Bad Request'}), 400)

@app.errorhandler(401)
def unauthorized_access(error):
	return make_response(jsonify({'error': 'Unautorized access'}), 401)
	
@app.errorhandler(403)
def forbidden(error):
	return make_response(jsonify({'error': 'Forbidden'}), 403)

@app.errorhandler(404)
def not_found(error):
	return make_response(jsonify({'error': 'Not found'}), 404)

@app.route('/rest-api/v1.0/pages', methods=['GET'])
@auth.login_required
def get_pages():
	username = auth.current_user()
	user_pages = []
	
	for user in users.find({"user_name": username}):
		user_id = user['user_id']
	for access1 in access.find({"list": user_id, "privilege": "Read"},{ "_id": 0 }):
		user_pages.append(access1['page_id'])
	
	pages_cursor = pages.find({"page_id": {"$in": user_pages}},{ "_id": 0 })
	pages_list = list(pages_cursor)	
	return jsonify({'pages': pages_list})

@app.route('/rest-api/v1.0/pages/<int:page_id>', methods=['GET'])
@auth.login_required
def get_page(page_id):
	
	username = auth.current_user()
	pages_cursor = pages.find({ },{ "_id": 0 })
	pages_list = list(pages_cursor)
	
	page = list(filter(lambda p: p['page_id'] == page_id, pages_list))
	if len(page) == 0:
		abort(404)
		
	for user in users.find({"user_name": username}):
		user_id = user['user_id']
	if access.find_one({"page_id": page_id, "list": user_id, "privilege": "Read"},{ "_id": 0 }) is None:
		abort(403)
	return jsonify({'page': page[0]})
	
@app.route('/rest-api/v1.0/pages', methods=['POST'])
def create_page():
	pages_cursor = pages.find({ },{ "_id": 0 })
	pages_list = list(pages_cursor)
	
	access_cursor = access.find({ },{ "_id": 0})
	access_list = list(access_cursor)
	
	if not request.json or not 'owner_id' in request.json or not 'tag' in request.json or not 'title' in request.json or not 'readaccess' in request.json or not 'writeaccess' in request.json:
		abort(400)
	
	if pages.find_one({"title": request.json['title']}) is not None:
		abort (400)
	if any(a > users_list[-1]['user_id'] for a in request.json['readaccess']):
		abort(400)
	if any(a < users_list[0]['user_id'] for a in request.json['readaccess']):
		abort(400)
	if any(a > users_list[-1]['user_id'] for a in request.json['writeaccess']):
		abort(400)
	if any(a < users_list[0]['user_id'] for a in request.json['writeaccess']):
		abort(400)
			
	doc = { 'page_id': pages_list[-1]['page_id'] + 1,
		'owner_id': request.json['owner_id'],
		'tag': request.json['tag'],
		'title': request.json['title'],
		'description': request.json.get('description', ""),
		'keywords': request.json.get('keywords', ""),
		'body': request.json.get('body', ""),
		'files': []}
	pages.insert_one(doc)
	
	access.insert_one({
		'acl_id': access_list[-1]['acl_id'] + 1,
		'page_id': pages_list[-1]['page_id'] + 1, 
		'privilege': 'Read',
		'list': request.json['readaccess']})
		
	access.insert_one({
		'acl_id': access_list[-1]['acl_id'] + 2,
		'page_id': pages_list[-1]['page_id'] + 1, 
		'privilege': 'Write',
		'list': request.json['writeaccess']})
	
	page = pages.find_one({"page_id": pages_list[-1]['page_id'] + 1},{ "_id": 0 })
	read_access = access.find_one({"acl_id": access_list[-1]['acl_id'] + 1, "page_id": pages_list[-1]['page_id'] + 1, "privilege": "Read"}, {"_id": 0})
	write_access = access.find_one({"acl_id": access_list[-1]['acl_id'] + 2, "page_id": pages_list[-1]['page_id'] + 1, "privilege": "Write"}, {"_id": 0})
	
	return jsonify({'page': page, 'access': {'read': read_access, 'write': write_access}}), 201

@app.route('/rest-api/v1.0/pages/<int:page_id>', methods=['PUT'])
@auth.login_required
def update_page(page_id):
	
	username = auth.current_user()
	pages_cursor = pages.find({ },{ "_id": 0 })
	pages_list = list(pages_cursor)
	
	page = list(filter(lambda p: p['page_id'] == page_id, pages_list))
	if len(page) == 0:
		abort(404)
	if not request.json:
		abort(400)
	if 'tag' in request.json and type(request.json['tag']) is not str:
		abort(400)
	if 'title' in request.json and (type(request.json['title']) is not str or pages.find_one({"title": request.json['title']}) is not None):
		abort(400)
	if 'description' in request.json and type(request.json['description']) is not str:
		abort(400)
	if 'keywords' in request.json and type(request.json['keywords']) is not str:
		abort(400)
	if 'body' in request.json and type(request.json['body']) is not str:
		abort(400)
			
	for user in users.find({"user_name": username}):
		user_id = user['user_id']
	if access.find_one({"page_id": page_id, "list": user_id, "privilege": "Write"},{ "_id": 0 }) is None:
		abort(403)
	
	pages.update_one({'page_id': page_id},
			{'$set':{
			'tag': request.json.get('tag', page[0]['tag']),
			'title': request.json.get('title', page[0]['title']),
			'description': request.json.get('description', page[0]['description']),
			'keywords': request.json.get('keywords', page[0]['keywords']),
			'body': request.json.get('body', page[0]['body'])}},
			upsert = False)
	
	page = pages.find_one({"page_id": page_id},{ "_id": 0 })
	
	return jsonify({'page': page})

@app.route('/rest-api/v1.0/pages/<int:page_id>', methods=['DELETE'])
@auth.login_required
def delete_page(page_id):
	
	username = auth.current_user()
	pages_cursor = pages.find({ },{ "_id": 0 })
	pages_list = list(pages_cursor)
	
	page = list(filter(lambda p: p['page_id'] == page_id, pages_list))
	if len(page) == 0:
		abort(404)
		
	for user in users.find({"user_name": username}):
		user_id = user['user_id']
	if access.find_one({"page_id": page_id, "list": user_id, "privilege": "Write"},{ "_id": 0 }) is None:
		abort(403)
	pages.delete_one({"page_id": page_id})
	access.delete_many({"page_id": page_id})
	result = "Page with id " + str(page_id) + " deleted."
	return jsonify({'result': result})
	
if __name__ == '__main__':
	app.run()
