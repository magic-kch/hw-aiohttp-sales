import json

from aiohttp import web
from aiohttp.web import HTTPConflict, HTTPNotFound, HTTPUnauthorized, HTTPForbidden, HTTPError

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
import bcrypt

from pydantic import ValidationError

from models import User, Session, Product, close_orm, init_orm
from schema import CreateUser, UpdateUser, CreateProduct, UpdateProduct
import base64


app = web.Application()

async def orm_contex(app: web.Application):
    print("START")
    await init_orm()
    yield
    await close_orm()
    print("FINISH")


@web.middleware
async def session_middleware(request, handler):
    async with Session() as session:
        print("before request")
        request.session = session
        result = await handler(request)
        print("after request")
        return result


app.cleanup_ctx.append(orm_contex)
app.middlewares.append(session_middleware)

def generate_error(error_cls, message):
    error = error_cls(
        text=json.dumps({"error": message}), content_type="application/json"
    )
    return error

def validate_json(json_data: dict, schema_class):
    try:
        schema_object = schema_class(**json_data)
        json_data_validated = schema_object.dict(exclude_unset=True)
        return json_data_validated
    except ValidationError as err:
        errors = err.errors()
        for error in errors:
            error.pop('ctx', None)
        raise generate_error(HTTPError, errors)

def hash_password(password: str, user_name: str):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

async def auth_check(session: AsyncSession, auth_header):
    if not auth_header:
        raise generate_error(HTTPError, 'Login or password not provided')
    if auth_header:
        decoded_auth_header = base64.b64decode(auth_header.split(' ')[1]).decode('utf-8')
        name, password = decoded_auth_header.split(':')
        result = await session.execute(select(User).filter_by(name=name))
        user = result.fetchone()
        if not user:
            raise generate_error(HTTPError, 'user not found')
        if not bcrypt.checkpw(password.encode('utf-8'), user[0].password.encode('utf-8')):
            raise generate_error(HTTPError, 'Password is incorrect')
        return user

async def get_user_by_id(session: AsyncSession, user_id: int):
    user = await session.get(User, user_id)
    if user is None:
        raise generate_error(HTTPNotFound, "user not found")
    return user


async def add_user(session: AsyncSession, user: User):
    session.add(user)
    try:
        print(user)
        await session.commit()
    except IntegrityError:
        raise generate_error(HTTPConflict, "user already exists")


async def get_product_by_id(session: AsyncSession, product_id: int):
    product = await session.get(Product, product_id)
    if product is None:
        raise generate_error(HTTPNotFound, "product not found")
    return product


class UserView(web.View):

    @property
    def user_id(self):
        return int(self.request.match_info["user_id"])


    async def get(self):
        user = await get_user_by_id(self.request.session, self.user_id)
        return web.json_response(user.dict)

    async def post(self):
        json_data = validate_json(await self.request.json(), CreateUser)
        json_data['password'] = hash_password(json_data['password'], json_data['name'])
        user = User(**json_data)
        await add_user(self.request.session, user)
        return web.json_response(user.id_dict)

    async def patch(self):
        auth_header = self.request.headers.get('Authorization')
        user = await auth_check(self.request.session, auth_header)
        if self.user_id != user[0].id:
            raise generate_error(HTTPForbidden, "Forbidden")

        json_data = validate_json(await self.request.json(), UpdateUser)
        if "password" in json_data:
            json_data['password'] = hash_password(json_data['password'])
        for key, value in json_data.items():
            setattr(user, key, value)
        await add_user(self.request.session, user)
        return web.json_response(user.id_dict)


    async def delete(self):
        auth_header = self.request.headers.get('Authorization')
        user = await auth_check(self.request.session, auth_header)
        if self.user_id != user[0].id:
            raise generate_error(HTTPForbidden, "Forbidden")
        self.request.session.delete(user)
        await self.request.session.commit()
        return web.json_response({"status": "deleted"})
    

class ProductView(web.View):

    @property
    def product_id(self):
        print("get product_id")
        return int(self.request.match_info["product_id"])


    async def get(self):
        product = await get_product_by_id(self.request.session, self.product_id)
        return web.json_response(product.dict)


    async def post(self):
        auth_header = self.request.headers.get('Authorization')
        user = await auth_check(self.request.session, auth_header)
        json_data = validate_json(await self.request.json(), CreateProduct)

        product = Product(**json_data)
        product.owner_id = user[0].id
        self.request.session.add(product)
        await self.request.session.commit()
        return web.json_response(product.id_dict)

    async def patch(self):
        auth_header = self.request.headers.get('Authorization')
        user = await auth_check(self.request.session, auth_header)
        print('user auth', user)
        json_data = validate_json(await self.request.json(), UpdateProduct)

        product = await get_product_by_id(self.request.session, self.product_id)

        if product.owner_id != user[0].id:
            raise generate_error(HTTPForbidden, "Forbidden")
        for key, value in json_data.items():
            setattr(product, key, value)
        self.request.session.add(product)
        await self.request.session.commit()
        return web.json_response(product.id_dict)

    async def delete(self):
        auth_header = self.request.headers.get('Authorization')
        user = await auth_check(self.request.session, auth_header)
        product = await get_product_by_id(self.request.session, self.product_id)

        if product.owner_id != user[0].id:
            generate_error(HTTPForbidden, "Forbidden")

        self.request.session.delete(product)
        await self.request.session.commit()
        return web.json_response({'status': 'deleted'})

class UserViewAll(web.View):
    async def get(self):
        result = await self.request.session.execute(select(User))
        users = result.fetchall()
        print(users)
        if not users:
            return web.json_response({"error": "No users found"})
        user_dicts = [user[0].dict for user in users]
        return web.json_response(user_dicts)


class ProductViewAll(web.View):
    async def get(self):
        result = await self.request.session.execute(select(Product))
        products = result.fetchall()
        if not products:
            return web.json_response({"error": "No products found"})
        products_dicts = [product[0].dict for product in products]
        return web.json_response(products_dicts)


class ProductViewRetrieve(web.View):
    async def get(self):
        user_id = int(self.request.match_info["user_id"])
        products = (await self.request.session.execute(select(Product).filter_by(owner_id=user_id))).scalars().all()
        if not products:
            return web.json_response({"error": "No products found"})
        return web.json_response([product.dict for product in products])



app.add_routes(
    [
        web.get("/user/{user_id:[0-9]+}", UserView),
        web.patch("/user/{user_id:[0-9]+}", UserView),
        web.delete("/user/{user_id:[0-9]+}", UserView),
        web.post("/user", UserView),
        web.get("/users", UserViewAll),
        web.get("/", ProductViewAll),
        web.get("/product/{product_id:[0-9]+}", ProductView),
        web.patch("/product/{product_id:[0-9]+}", ProductView),
        web.delete("/product/{product_id:[0-9]+}", ProductView),
        web.post("/product", ProductView),
        web.get("/user/{user_id:[0-9]+}/products/", ProductViewRetrieve),
    ]
)

web.run_app(app)