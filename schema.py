from pydantic import BaseModel, field_validator


class BaseUser(BaseModel):
    password: str

    @field_validator('password')
    @classmethod
    def check_password(cls, value: str):
        if len(value) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return value


class CreateUser(BaseUser):
    name: str
    password: str
    email: str


class UpdateUser(BaseUser):
    name: str | None = None
    password: str | None = None
    email: str | None = None


class BaseProduct(BaseModel):
    price: int
    count: int


    @field_validator('price', 'count')
    @classmethod
    def check_price(cls, value: int):
        if value < 0:
            raise ValueError('Value cannot be negative')
        return value


class CreateProduct(BaseProduct):
    # owner_id: int
    name: str
    description: str
    price: int
    count: int
    image: str | None = None

class UpdateProduct(BaseProduct):
    name: str | None = None
    description: str | None = None
    price: int | None = None
    count: int | None = None
    image: str | None = None
    