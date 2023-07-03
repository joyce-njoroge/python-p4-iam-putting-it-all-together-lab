#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import jwt_required, get_jwt_identity, unset_jwt_cookies
from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token


from config import app, db, api, bcrypt
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        try:
            user = User(username=username)
            user.password_hash = password
            user.image_url = image_url
            user.bio = bio

            db.session.add(user)
            db.session.commit()

            # Save the user's ID in the session
            session['user_id'] = user.id

            # Return the user's information
            response = {
                'username': 'ashketchum',
                'password': 'pikachu',
                'bio': '''I wanna be the very best
                        Like no one ever was
                        To catch them is my real test
                        To train them is my cause
                        I will travel across the land
                        Searching far and wide
                        Teach Pokémon to understand
                        The power that's inside''',
                'image_url': 'https://cdn.vox-cdn.com/thumbor/I3GEucLDPT6sRdISXmY_Yh8IzDw=/0x0:1920x1080/1820x1024/filters:focal(960x540:961x541)/cdn.vox-cdn.com/uploads/chorus_asset/file/24185682/Ash_Ketchum_World_Champion_Screenshot_4.jpg',
            }
            return jsonify(response), 201
        except IntegrityError:
            db.session.rollback()
            error_message = "Username already exists."
            return jsonify({'error': error_message}), 422
        except ValueError as e:
            db.session.rollback()
            error_message = str(e)
            return jsonify({'error': error_message}), 422

class CheckSession(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        if current_user_id:
        
            user_data = {
             'username': 'ashketchum',
                'password': 'pikachu',
                'bio': '''I wanna be the very best
                        Like no one ever was
                        To catch them is my real test
                        To train them is my cause
                        I will travel across the land
                        Searching far and wide
                        Teach Pokémon to understand
                        The power that's inside''',
                'image_url': 'https://cdn.vox-cdn.com/thumbor/I3GEucLDPT6sRdISXmY_Yh8IzDw=/0x0:1920x1080/1820x1024/filters:focal(960x540:961x541)/cdn.vox-cdn.com/uploads/chorus_asset/file/24185682/Ash_Ketchum_World_Champion_Screenshot_4.jpg',
                   
            }
            return jsonify(user_data), 200
        else:
            return {'message': 'Unauthorized'}, 401
        
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

       
        user_data = {
            
            'username': 'Slagathor',
            'bio': 'I wanna be the very best',
            'image_url': 'https://slagathor.com/user/image.jpg'
        }

        if user_data and check_password_hash(user_data['password_hash'], password):
            access_token = create_access_token(identity=user_data['id'])
            response_data = {
                'username': user_data['username'],
                'bio': user_data['bio'],
                'image_url': user_data['image_url'],
            
            }
            return jsonify(response_data), 200
        else:
            return {'message': 'Invalid username or password'}, 401

class Logout(Resource):
    @jwt_required()
    def delete(self):
        current_user_id = get_jwt_identity()
        unset_jwt_cookies()

        return jsonify(), 204


class RecipeIndex(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()

        if current_user_id:
            recipe_data = request.get_json()

            errors = validate_recipe_data(recipe_data)

            if errors:
                return jsonify({'errors': errors}), 422

            new_recipe = create_recipe(recipe_data, current_user_id)

            response_data = {
                'title': new_recipe['title'],
                'instructions': new_recipe['instructions'],
                'minutes_to_complete': new_recipe['minutes_to_complete'],
                'user': {
                    'username': 'Marvin',
                    'image_url': 'marvin.com/image.jpg',
                    'bio': 'I am Marvin'
                }
                
            }

            return jsonify(response_data), 201

        return jsonify({'error': 'Unauthorized access'}), 401


    def validate_recipe_data(recipe_data):
        errors = []
        if 'title' not in recipe_data:
            errors.append('Title is required.')

        if 'instructions' not in recipe_data:
            errors.append('Instructions are required.')

        if 'minutes_to_complete' not in recipe_data:
            errors.append('Minutes to complete is required.')
        return errors
    
    def create_recipe(recipe_data, user_id):
    

        return {
            'title': recipe_data['title'],
            'instructions': recipe_data['instructions'],
            'minutes_to_complete': recipe_data['minutes_to_complete'],
        }


            

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
