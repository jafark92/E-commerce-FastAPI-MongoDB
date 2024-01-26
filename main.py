# from routers import products#, cart, purchase, admin
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Dict, Optional, List
from pydantic import BaseModel, HttpUrl, EmailStr
from typing import Annotated

# Authentications
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone


app = FastAPI()

# Include routers
# app.include_router(products.router)
# app.include_router(cart.router)
# app.include_router(purchase.router)
# app.include_router(admin.router)

# MongoDB connection details
MONGO_DETAILS = "mongodb+srv://jafar:4206lEk92mPLChBr@e-commerce.xxqjdba.mongodb.net/"  # Replace with your connection string
client = AsyncIOMotorClient(MONGO_DETAILS)
db = client.db  # reference to database db
products_collection = db.products
customers_collection = db.customers


# Secret key and algorithm for JWT
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

# Access token expiration time
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI security
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Models Dicts
class Product(BaseModel):
    id: str
    name: str
    price: float
    category: str
    stock: int
    created_at: datetime
    updated_at: Optional[datetime] = None

class CartItem(BaseModel):
    product_id: str
    quantity: int

class Customer(BaseModel):
    username: str
    name: str
    email: EmailStr
    password: str
    created_at: datetime = datetime.now()
    updated_at: Optional[datetime] = None
    cart: List[CartItem] = []

class Token(BaseModel):
    access_token: str
    token_type: str


# Function to get a customer by username
async def get_customer_by_username(username: str):
    customer = await customers_collection.find_one({"username": username})
    return Customer(**customer) if customer else None

# Function to authenticate a customer
async def authenticate_customer(username: str, password: str):
    customer = await get_customer_by_username(username)
    if not customer:
        return None
    if not password==customer.password:
        return None
    return customer

# Function to create an access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency to get the current customer
async def get_current_customer(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    customer = await get_customer_by_username(username)
    if customer is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return customer


@app.post("/signup")
async def signup(customer: Customer):
    # Insert customer data into the collection
    inserted_customer = await customers_collection.insert_one(customer.model_dump())

    # Check if insertion was successful
    if inserted_customer.acknowledged:
        return {"message": "Customer created successfully", "customer_id": str(inserted_customer.inserted_id)}
    else:
        raise HTTPException(status_code=500, detail="Failed to create customer")

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    customer = await authenticate_customer(form_data.username, form_data.password)
    print(customer)
    if not customer:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": customer.username, "scopes": form_data.scopes},
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")

# Route to get the current customer's profile
@app.get("/profile", response_model=Customer)
async def get_profile(current_customer: Customer = Depends(get_current_customer)):
    return current_customer

# ===========================================

@app.post("/customers/{customer_id}/cart")
async def add_to_cart(customer_id: str, item: CartItem):
    # Logic to add item to customer's cart
    pass

@app.get("/customers/{customer_id}/cart")
async def view_cart(customer_id: str):
    # Logic to view the cart
    pass

@app.delete("/customers/{customer_id}/cart/{product_id}")
async def remove_from_cart(customer_id: str, product_id: str):
    # Logic to remove an item from the cart
    pass

# ===========================================

# Endpoint to add a product
@app.post("/product")
async def add_product(product: Product):
    existing_product = await products_collection.find_one({"id": product.id})
    if existing_product:
        raise HTTPException(status_code=400, detail="Product already exists")

    await products_collection.insert_one(product.model_dump())
    return {"message": "Product added successfully"}

# Remove a product
@app.delete("/products/{product_id}")
async def remove_product(product_id: str):
    delete_result = await products_collection.delete_one({"id": product_id})

    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")

    return {"message": "Product removed successfully"}

# Search products
@app.get("/products/search", response_model=List[Product])
async def search_products(category: str):
    query = {"category": category.lower()}
    results = await products_collection.find(query).to_list(100)
    return [Product(**result) for result in results]