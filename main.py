from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from mongoengine import connect, disconnect
from datetime import timedelta
from typing import List
import json
from bson import json_util

from config import MONGODB_URL, ACCESS_TOKEN_EXPIRE_MINUTES
from models.user import User
from models.project import Project
from models.schemas import (  # Updated import path
    UserCreate,
    UserResponse,
    ProjectCreate,
    ProjectResponse,
    Token,
    UserRole
)
from auth.jwt_handler import (
    get_password_hash,
    verify_password,
    create_access_token,
    decode_token,
)

app = FastAPI(title="FastAPI JWT RBAC")
security = HTTPBearer()

# Connect to MongoDB
connect(host=MONGODB_URL)


# Helper function to convert MongoDB document to dict
def parse_json(data):
    return json.loads(json_util.dumps(data))


# Dependency to get current user
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = User.objects(username=username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# Admin role verification
def verify_admin(user: User = Depends(get_current_user)):
    if user.role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to perform this action"
        )
    return user


# User registration
@app.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    if User.objects(username=user_data.username).first():
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )

    hashed_password = get_password_hash(user_data.password)
    user = User(
        username=user_data.username,
        password=hashed_password,
        role=user_data.role
    )
    user.save()

    return UserResponse(
        id=str(user.id),
        username=user.username,
        role=UserRole(user.role)
    )


# User login
@app.post("/login", response_model=Token)
async def login(username: str, password: str):
    user = User.objects(username=username).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username, "role": user.role},
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


# Get all projects (accessible by all authenticated users)
@app.get("/projects", response_model=List[ProjectResponse])
async def get_projects(user: User = Depends(get_current_user)):
    projects = Project.objects()
    return [
        ProjectResponse(
            id=str(project.id),
            name=project.name,
            description=project.description,
            created_at=project.created_at
        )
        for project in projects
    ]


# Create project (admin only)
@app.post("/projects", response_model=ProjectResponse)
async def create_project(
        project_data: ProjectCreate,
        user: User = Depends(verify_admin)
):
    project = Project(
        name=project_data.name,
        description=project_data.description
    )
    project.save()

    return ProjectResponse(
        id=str(project.id),
        name=project.name,
        description=project.description,
        created_at=project.created_at
    )


# Update project (admin only)
@app.put("/projects/{project_id}", response_model=ProjectResponse)
async def update_project(
        project_id: str,
        project_data: ProjectCreate,
        user: User = Depends(verify_admin)
):
    project = Project.objects(id=project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project.name = project_data.name
    project.description = project_data.description
    project.save()

    return ProjectResponse(
        id=str(project.id),
        name=project.name,
        description=project.description,
        created_at=project.created_at
    )


# Delete project (admin only)
@app.delete("/projects/{project_id}")
async def delete_project(project_id: str, user: User = Depends(verify_admin)):
    project = Project.objects(id=project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project.delete()
    return {"message": "Project deleted successfully"}


@app.on_event("shutdown")
def shutdown_event():
    disconnect()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
