# Standard library imports
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from mongoengine import connect, disconnect
from datetime import timedelta
from typing import List
import json
from bson import json_util
from starlette.responses import JSONResponse

# Local application imports
from config import MONGODB_URL, ACCESS_TOKEN_EXPIRE_MINUTES
from models.user import User
from models.project import Project
from models.schemas import (
    UserCreate,
    UserResponse,
    ProjectCreate,
    ProjectResponse,
    Token,
    UserRole,
)
from auth.jwt_handler import (
    get_password_hash,
    verify_password,
    create_access_token,
    decode_token,
)

# Initialize FastAPI application with title
app = FastAPI(title="FastAPI JWT RBAC")
security = HTTPBearer()

# Establish MongoDB connection
connect(host=MONGODB_URL)


# Helper Functions
def parse_json(data):
    """
    Convert MongoDB document to JSON-compatible dictionary.

    Args:
        data: MongoDB document to be converted

    Returns:
        dict: JSON-compatible dictionary
    """
    return json.loads(json_util.dumps(data))


# Authentication Dependencies
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Dependency function to get the current authenticated user from JWT token.

    Args:
        credentials: HTTP Bearer token credentials

    Returns:
        User: Current authenticated user object

    Raises:
        HTTPException: If token is invalid or user not found
    """
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = User.objects(username=username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def verify_admin(user: User = Depends(get_current_user)):
    """
    Dependency function to verify if the current user has admin privileges.

    Args:
        user: Current authenticated user

    Returns:
        User: Current authenticated admin user

    Raises:
        HTTPException: If user is not an admin
    """
    if user.role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to perform this action"
        )
    return user


# API Endpoints
@app.post("/register",
          response_model=UserResponse,
          responses={
              201: {"description": "User successfully registered"},
              400: {"description": "Bad Request"},
              422: {"description": "Validation Error"},
              500: {"description": "Internal Server Error"}
          })
async def register(user_data: UserCreate):
    """
    Register a new user with username, password, and role.

    Args:
        user_data: UserCreate model containing registration information

    Returns:
        UserResponse: Created user information

    Raises:
        HTTPException: If registration fails due to validation or server errors
    """
    try:
        # Validate username length
        if len(user_data.username) < 3 or len(user_data.username) > 30:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username must be between 3 and 30 characters"
            )

        # Validate password length
        if len(user_data.password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters long"
            )

        # Check if username already exists
        if User.objects(username=user_data.username).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )

        # Create and save new user
        hashed_password = get_password_hash(user_data.password)
        user = User(
            username=user_data.username.lower(),
            password=hashed_password,
            role=user_data.role
        )
        user.save()

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=UserResponse(
                id=str(user.id),
                username=user.username,
                role=UserRole(user.role)
            ).dict()
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.post("/login",
          response_model=Token,
          responses={
              200: {"description": "Successfully logged in"},
              401: {"description": "Unauthorized"},
              422: {"description": "Validation Error"},
              500: {"description": "Internal Server Error"}
          })
async def login(username: str, password: str):
    """
    Authenticate user and generate JWT token.

    Args:
        username: User's username
        password: User's password

    Returns:
        Token: JWT access token for authenticated user

    Raises:
        HTTPException: If login fails due to invalid credentials or server errors
    """
    try:
        # Verify user credentials
        user = User.objects(username=username.lower()).first()
        if not user or not verify_password(password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        # Generate JWT token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": username, "role": user.role},
            expires_delta=access_token_expires
        )
        return Token(access_token=access_token, token_type="bearer")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


# Project Management Endpoints
@app.get("/projects", response_model=List[ProjectResponse])
async def get_projects(user: User = Depends(get_current_user),
                       page: int = Query(1, ge=1, description="Page number (starting from 1)"),
                       page_size: int = Query(10, ge=1, le=100, description="Number of items per page (1-10)"),):
    """
    Retrieve paginated projects (accessible by all authenticated users).

    Args:
        user: Current authenticated user
        page: Page number for pagination
        page_size: Number of items per page

    Returns:
        List[ProjectResponse]: List of paginated projects

    Raises:
        HTTPException: If retrieval fails due to server errors
    """
    try:
        projects = Project.objects()
        total_projects = projects.count()
        start = (page - 1) * page_size
        end = start + page_size

        paginated_projects = projects[start:end]
        return [
            ProjectResponse(
                id=str(project.id),
                name=project.name,
                description=project.description,
                created_at=project.created_at
            )
            for project in paginated_projects
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.post("/projects", response_model=ProjectResponse)
async def create_project(project_data: ProjectCreate, user: User = Depends(verify_admin)):
    """
    Create a new project (admin only).

    Args:
        project_data: ProjectCreate model containing project information
        user: Current authenticated admin user

    Returns:
        ProjectResponse: Created project information

    Raises:
        HTTPException: If creation fails due to validation or server errors
    """
    try:
        # Validate project data
        if not project_data.name or not project_data.description:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Project name and description are required"
            )

        # Create and save project
        project = Project(
            name=project_data.name,
            description=project_data.description,
            created_by=user.username
        )
        project.save()

        return ProjectResponse(
            id=str(project.id),
            name=project.name,
            description=project.description,
            created_at=project.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.put("/projects/{project_id}", response_model=ProjectResponse)
async def update_project(
        project_id: str,
        project_data: ProjectCreate,
        user: User = Depends(verify_admin)):
    """
    Update an existing project (admin only).

    Args:
        project_id: ID of the project to update
        project_data: ProjectCreate model containing updated information
        user: Current authenticated admin user

    Returns:
        ProjectResponse: Updated project information

    Raises:
        HTTPException: If update fails due to validation, permissions, or server errors
    """
    try:
        # Validate project data
        if not project_data.name or not project_data.description:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Project name and description are required"
            )

        # Find and validate project
        project = Project.objects(id=project_id).first()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )

        # Verify creator permissions
        if project.created_by != user.username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only creators are allowed to make changes"
            )

        # Update project
        project.name = project_data.name
        project.description = project_data.description
        project.save()

        return ProjectResponse(
            id=str(project.id),
            name=project.name,
            description=project.description,
            created_at=project.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.delete("/projects/{project_id}")
async def delete_project(project_id: str, user: User = Depends(verify_admin)):
    """
    Delete an existing project (admin only).

    Args:
        project_id: ID of the project to delete
        user: Current authenticated admin user

    Returns:
        dict: Success message

    Raises:
        HTTPException: If deletion fails due to permissions or server errors
    """
    try:
        # Find and validate project
        project = Project.objects(id=project_id).first()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )

        # Delete project
        project.delete()
        return {"message": "Project deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


# Shutdown Event Handler
@app.on_event("shutdown")
def shutdown_event():
    """
    Disconnect from MongoDB when the application shuts down.
    """
    disconnect()


# Main entry point
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
