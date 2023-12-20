from flask import Flask, Blueprint, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///games.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Hello'

db = SQLAlchemy(app)
jwt = JWTManager(app)

users_bp = Blueprint('users', __name__)
games_bp = Blueprint('games', __name__)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    genre = db.Column(db.String(50), nullable=False)
    platform = db.Column(db.String(50), nullable=False)

    def __init__(self, title, genre, platform):
        self.title = title
        self.genre = genre
        self.platform = platform


@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@users_bp.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=username)
    return jsonify({'access_token': access_token}), 200


@games_bp.route('/games', methods=['GET'])
@jwt_required()
def get_games():
    games = Game.query.all()
    result = []
    for game in games:
        game_data = {
            'id': game.id,
            'title': game.title,
            'genre': game.genre,
            'platform': game.platform
        }
        result.append(game_data)
    return jsonify(result), 200


def add_game():
    data = request.get_json()
    title = data.get('title')
    genre = data.get('genre')
    platform = data.get('platform')

    if not title or not genre or not platform:
        return jsonify({'message': 'Title, genre, and platform are required'}), 400

    new_game = Game(title=title, genre=genre, platform=platform)
    db.session.add(new_game)
    db.session.commit()

    return jsonify({'message': 'Game added successfully'}), 201


@games_bp.route('/games/<int:game_id>', methods=['GET'])
@jwt_required()
def get_game(game_id):
    game = Game.query.get(game_id)
    if game:
        game_data = {
            'id': game.id,
            'title': game.title,
            'genre': game.genre,
            'platform': game.platform
        }
        return jsonify(game_data), 200
    else:
        return jsonify({'message': 'Game not found'}), 404


@games_bp.route('/games/<int:game_id>', methods=['PUT'])
@jwt_required()
def update_game(game_id):
    game = Game.query.get(game_id)
    if game:
        data = request.get_json()
        game.title = data.get('title', game.title)
        game.genre = data.get('genre', game.genre)
        game.platform = data.get('platform', game.platform)

        db.session.commit()
        return jsonify({'message': 'Game updated successfully'}), 200
    else:
        return jsonify({'message': 'Game not found'}), 404


@games_bp.route('/games/<int:game_id>', methods=['DELETE'])
@jwt_required()
def delete_game(game_id):
    game = Game.query.get(game_id)
    if game:
        db.session.delete(game)
        db.session.commit()
        return jsonify({'message': 'Game deleted successfully'}), 200
    else:
        return jsonify({'message': 'Game not found'}), 404


if __name__ == '__main__':
    db.create_all()
    app.register_blueprint(games_bp)
    app.run(debug=True)
