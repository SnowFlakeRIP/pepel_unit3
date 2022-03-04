from peewee import *
from http.server import *
import urllib.parse as urlparse
import json

connection = SqliteDatabase('pepel_unit3.sqlite')


class BaseModel(Model):
    class Meta:
        database = connection


class Users(BaseModel):
    user_id = AutoField()
    email = CharField()


class News(BaseModel):
    news_id = AutoField()
    user_id = ForeignKeyField(model=Users, backref='users_news')
    title = TextField()
    text = TextField()


class Roles(BaseModel):
    role_id = AutoField()
    role_name = CharField()


class UserRoles(BaseModel):
    user_role_id = AutoField()
    user_id = ForeignKeyField(model=Users, backref='user')
    role_id = ForeignKeyField(model=Roles, backref='role')

    class Meta:
        table_name = 'user_roles'


connection.create_tables([
    Users, News, Roles, UserRoles
])


class Server(BaseHTTPRequestHandler):
    error_message = {
        "message": "Some problems"
    }

    def end_response(self, response):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def server_error(self):
        self.send_response(500)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(Server.error_message).encode())
        return None

    def get_data(self):
        length = int(self.headers['Content-length'])
        post_data = self.rfile.read(length)
        data = post_data.decode('utf-8')
        data = json.loads(data)
        return data

    def do_POST(self):
        if self.path == '/add_news':
            try:
                data = Server.get_data(self)
                if data.get('text') == None:
                    Server.end_response(self, {
                        "error": "Parameter 'text' is required"
                    })
                    return None
                if data.get('user_id') == None:
                    Server.end_response(self, {
                        "error": "Parameter 'user_id' is required"
                    })
                    return None
                if data.get('title') == None:
                    Server.end_response(self, {
                        "error": "Parameter 'title' is required"
                    })
                    return None
                user_id = data["user_id"]
                title = data["title"]
                text = data["text"]
                News.create(user_id=user_id, title=title, text=text)
                Server.end_response(self, {
                    "message": "News has been successfuly created"
                })
            except:
                Server.server_error(self)
        elif self.path == '/add_user':
            try:
                data = Server.get_data(self)
                if data.get('email') == None:
                    Server.end_response(self, {
                        "error": "Parameter 'email' is required"
                    })
                    return None
                email = data["email"]
                Users.create(email=email)
                Server.end_response(self, {
                    "message": "User has been successfuly created"
                })
            except:
                Server.server_error(self)
        elif self.path == '/add_role':
            try:
                data = Server.get_data(self)
                if data.get('role_name') == None:
                    Server.end_response(self, {
                        "error": "Parameter 'role_name' is required"
                    })
                    return None
                role_name = data["role_name"]
                Roles.create(role_name=role_name)
                Server.end_response(self, {
                    "message": "Role has been successfuly created"
                })
            except:
                Server.server_error(self)
        elif self.path == '/add_user_role':
            try:
                data = Server.get_data(self)
                if data.get('role_id') == None:
                    Server.end_response(self, {
                        "error": "Parameter 'role_id' is required"
                    })
                    return None
                if data.get('user_id') == None:
                    Server.end_response(self, {
                        "error": "Parameter 'user_id' is required"
                    })
                role_id = data["role_id"]
                user_id = data["user_id"]
                UserRoles.create(role_id=role_id, user_id=user_id)
                Server.end_response(self, {
                    "message": "Users role has been successfuly created"
                })
            except:
                Server.server_error(self)

    def do_GET(self):
        if self.path == '/get_news':
            try:
                response = []
                query = News.select()
                for item in query:
                    response.append(
                        {"news_id": item.news_id, "user_id": item.user_id.user_id, "title": item.title,
                         "text": item.text}
                    )
                Server.end_response(self, response)
            except:
                Server.server_error(self)
        elif self.path.startswith('/get_news?'):
            try:
                response = []
                parsed = urlparse.urlparse(self.path)
                querys = urlparse.parse_qs(parsed.query)
                query = News.select().where(News.news_id == querys["id"])
                for item in query:
                    response.append(
                        {"news_id": item.news_id, "user_id": item.user_id.user_id, "title": item.title,
                         "text": item.text}
                    )
                if len(response) == 0:
                    Server.end_response(self, {
                        "message": f"News with id = {querys['id'][0]} is not exist"
                    })
                    return None
                Server.end_response(self, response)
            except:
                Server.server_error(self)
        elif self.path == '/get_users':
            try:
                response = []
                query = Users.select()
                for item in query:
                    response.append(
                        {"user_id": item.user_id, "email": item.email}
                    )
                Server.end_response(self, response)
            except:
                Server.server_error(self)
        elif self.path.startswith('/get_users?'):
            try:
                response = []
                parsed = urlparse.urlparse(self.path)
                querys = urlparse.parse_qs(parsed.query)
                query = Users.select().where(Users.user_id == querys["id"])
                for item in query:
                    response.append(
                        {"user_id": item.user_id, "email": item.email}
                    )
                if len(response) == 0:
                    Server.end_response(self, {
                        "message": f"User with id = {querys['id'][0]} is not exist"
                    })
                    return None
                Server.end_response(self, response)
            except:
                Server.server_error(self)
        elif self.path == '/get_users_roles':
            try:
                response = []
                query = UserRoles.select()
                for item in query:
                    user = UserRoles.get(UserRoles.user_id == item)
                    user_email = Users.get(Users.user_id == user.user_id).email
                    user_role = Roles.get(Roles.role_id == user.role_id).role_name
                    response.append(
                        {"user_role_id": item.user_role_id, "user": user_email,
                         "role_id": user_role}
                    )
                Server.end_response(self, response)
            except:
                Server.server_error(self)
        elif self.path.startswith('/get_users_roles?'):
            try:
                response = []
                parsed = urlparse.urlparse(self.path)
                querys = urlparse.parse_qs(parsed.query)
                query = UserRoles.select().where(UserRoles.user_id == querys["id"])
                for item in query:
                    user = UserRoles.get(UserRoles.user_id == item)
                    user_email = Users.get(Users.user_id == user.user_id).email
                    user_role = Roles.get(Roles.role_id == user.role_id).role_name
                    response.append(
                        {"user_role_id": item.user_role_id, "user": user_email,
                         "role_id": user_role}
                    )
                if len(response) == 0:
                    Server.end_response(self, {
                        "message": f"User with id = {querys['id'][0]} is not exist"
                    })
                    return None
                Server.end_response(self, response)
            except:
                Server.server_error(self)


HTTPServer(('localhost', 8000), Server).serve_forever()

connection.close()
