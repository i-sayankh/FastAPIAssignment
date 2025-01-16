# Standard library imports
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from mongoengine import connect, disconnect
from datetime import timedelta
from typing import List
import json
from bson import json_util, ObjectId
from starlette.responses import JSONResponse
import uuid

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
    ErrorResponses
)
from auth.jwt_handler import (
    get_password_hash,
    verify_password,
    create_access_token,
    decode_token,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for handling application startup and shutdown events.

    Args:
        app: FastAPI application instance
    """
    # Startup operations (if any) go here
    yield

    # Shutdown operations
    disconnect()


# Initialize FastAPI application with title
app = FastAPI(title="FastAPI JWT RBAC", lifespan=lifespan)
security = HTTPBearer()

# Establish MongoDB connection
connect(host=MONGODB_URL)


# Helper Functions --
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


def validate_uuid(project_id: str):
    try:
        uuid_obj = uuid.UUID(project_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid project ID format, Project Not Found"
        )


# API Endpoints
@app.post("/register",
          response_model=UserResponse,
          responses={
              201: {
                  "description": "User created successfully",
                  "content": {
                      "application/json": {
                          "example": {
                              "id": "507f1f77bcf86cd799439011",
                              "username": "john_doe",
                              "email": "john@example.com",
                              "role": "user",
                              "created_at": "2024-01-09T10:00:00"
                          }
                      }
                  }
              },
              400: {
                  "description": "Registration validation error",
                  "content": {
                      "application/json": {
                          "examples": {
                              "username_exists": {
                                  "summary": "Username already taken",
                                  "value": {"detail": ErrorResponses.USERNAME_EXISTS}
                              },
                              "invalid_username": {
                                  "summary": "Invalid username format",
                                  "value": {"detail": ErrorResponses.INVALID_USERNAME}
                              },
                              "weak_password": {
                                  "summary": "Password too weak",
                                  "value": {
                                      "detail": ErrorResponses.WEAK_PASSWORD,
                                      "requirements": {
                                          "min_length": 8,
                                          "must_contain": ["uppercase", "lowercase", "number", "special_char"]
                                      }
                                  }
                              },
                              "email_exists": {
                                  "summary": "Email already registered",
                                  "value": {"detail": ErrorResponses.EMAIL_EXISTS}
                              },
                              "invalid_email": {
                                  "summary": "Invalid email format",
                                  "value": {"detail": ErrorResponses.INVALID_EMAIL}
                              }
                          }
                      }
                  }
              },
              422: {
                  "description": "Request validation error",
                  "content": {
                      "application/json": {
                          "example": {
                              "detail": [
                                  {
                                      "loc": ["body", "username"],
                                      "msg": "field required",
                                      "type": "value_error.missing"
                                  }
                              ]
                          }
                      }
                  }
              },
              500: {
                  "description": "Internal server error",
                  "content": {
                      "application/json": {
                          "example": {
                              "detail": "Internal server error occurred. Please try again later."
                          }
                      }
                  }
              }
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
            )
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.post("/login",
          response_model=Token,
          responses={
              200: {
                  "description": "Successfully logged in",
                  "content": {
                      "application/json": {
                          "example": {
                              "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                              "token_type": "bearer",
                              "expires_in": 3600
                          }
                      }
                  }
              },
              401: {
                  "description": "Authentication failed",
                  "content": {
                      "application/json": {
                          "examples": {
                              "invalid_credentials": {
                                  "summary": "Invalid credentials",
                                  "value": {"detail": ErrorResponses.INVALID_CREDENTIALS}
                              }
                          }
                      }
                  }
              },
              422: {
                  "description": "Request validation error",
                  "content": {
                      "application/json": {
                          "example": {
                              "detail": [
                                  {
                                      "loc": ["body", "username"],
                                      "msg": "field required",
                                      "type": "value_error.missing"
                                  }
                              ]
                          }
                      }
                  }
              },
              500: {
                  "description": "Internal server error",
                  "content": {
                      "application/json": {
                          "example": {
                              "detail": "Internal server error occurred. Please try again later."
                          }
                      }
                  }
              }
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
@app.get("/projects/{project_id}", response_model=ProjectResponse,
         responses={
             200: {
                 "description": "Successfully retrieved project",
                 "content": {
                     "application/json": {
                         "example": {
                             "id": "507f1f77bcf86cd799439011",  # Example UUID
                             "name": "Project Name",
                             "description": "Project description",
                             "created_at": "2024-01-09T10:00:00"
                         }
                     }
                 }
             },
             403: {
                 "description": "Authentication error",
                 "content": {
                     "application/json": {
                         "examples": {
                             "not_authenticated": {
                                 "summary": "No authentication provided",
                                 "value": {"detail": ErrorResponses.NOT_AUTHENTICATED}
                             },
                             "token_expired": {
                                 "summary": "Token expired",
                                 "value": {"detail": ErrorResponses.TOKEN_EXPIRED}
                             },
                             "invalid_token": {
                                 "summary": "Invalid token",
                                 "value": {"detail": ErrorResponses.INVALID_TOKEN}
                             }
                         }
                     }
                 }
             },
             404: {
                 "description": "Project not found",
                 "content": {
                     "application/json": {
                         "example": {"detail": ErrorResponses.PROJECT_NOT_FOUND}
                     }
                 }
             },
             500: {
                 "description": "Internal server error",
                 "content": {
                     "application/json": {
                         "example": {"detail": ErrorResponses.SERVER_ERROR}
                     }
                 }
             }
         })
async def get_project_by_id(project_id: str, user: User = Depends(get_current_user)):
    """
    Retrieve a specific project by ID.

    Args:
        project_id: ID of the project to retrieve (UUID)
        user: Current authenticated user

    Returns:
        ProjectResponse: Project information

    Raises:
        HTTPException: If project not found or server errors occur
    """
    # Validate project_id format (UUID)
    validate_uuid(project_id)  # You may want to rename this function to validate_uuid if necessary
    try:
        project = Project.objects(_id=project_id).first()  # Query using _id (UUID)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponses.PROJECT_NOT_FOUND
            )

        return ProjectResponse(
            id=str(project._id),  # Use _id here
            name=project.name,
            description=project.description,
            created_at=project.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponses.SERVER_ERROR
        )

@app.get("/projects", response_model=List[ProjectResponse],
         responses={
             200: {
                 "description": "Successfully retrieved projects",
                 "content": {
                     "application/json": {
                         "example": [{
                             "id": "507f1f77bcf86cd799439011",
                             "name": "Sample Project",
                             "description": "Project description",
                             "created_at": "2024-01-09T10:00:00"
                         }]
                     }
                 }
             },
             403: {
                 "description": "Authentication error",
                 "content": {
                     "application/json": {
                         "examples": {
                             "not_authenticated": {
                                 "summary": "No authentication provided",
                                 "value": {"detail": ErrorResponses.INSUFFICIENT_PERMISSIONS}
                             },
                             "token_expired": {
                                 "summary": "Token expired",
                                 "value": {"detail": ErrorResponses.TOKEN_EXPIRED}
                             },
                             "invalid_token": {
                                 "summary": "Invalid token",
                                 "value": {"detail": ErrorResponses.INVALID_TOKEN}
                             }
                         }
                     }
                 }
             },
             404: {
                 "description": "Project not found",
                 "content": {
                     "application/json": {
                         "example": {"detail": ErrorResponses.PROJECT_NOT_FOUND}
                     }
                 }
             },
             500: {
                 "description": "Internal server error",
                 "content": {
                     "application/json": {
                         "example": {"detail": ErrorResponses.SERVER_ERROR}
                     }
                 }
             }
         })
async def get_projects(user: User = Depends(get_current_user),
                       page: int = Query(1, ge=1, description="Page number (starting from 1)"),
                       page_size: int = Query(10, ge=1, le=100, description="Number of items per page (1-10)")):
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
        # Validate user authentication
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ErrorResponses.INSUFFICIENT_PERMISSIONS
            )

        # Get projects
        projects = Project.objects()  # Retrieve all projects
        total_projects = projects.count()
        start = (page - 1) * page_size
        end = start + page_size

        # Handle pagination
        paginated_projects = projects[start:end]
        
        # Return formatted response
        return [
            ProjectResponse(
                id=str(project._id),  # Using _id instead of id based on Project model
                name=project.name,
                description=project.description,
                created_at=project.created_at
            )
            for project in paginated_projects
        ]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponses.SERVER_ERROR
        )


@app.post("/projects", response_model=ProjectResponse,
          responses={
              201: {
                  "description": "Project created successfully",
                  "content": {
                      "application/json": {
                          "example": {
                              "id": "507f1f77bcf86cd799439011",
                              "name": "New Project",
                              "description": "Project description",
                              "created_at": "2024-01-09T10:00:00"
                          }
                      }
                  }
              },
              400: {
                  "description": "Invalid request data",
                  "content": {
                      "application/json": {
                          "example": {"detail": ErrorResponses.INVALID_DATA}
                      }
                  }
              },
              401: {
                  "description": "Unauthorized access",
                  "content": {
                      "application/json": {
                          "example": {"detail": ErrorResponses.INSUFFICIENT_PERMISSIONS}
                      }
                  }
              },
              403: {
                  "description": "Forbidden - Not an admin",
                  "content": {
                      "application/json": {
                          "example": {"detail": ErrorResponses.NOT_ADMIN}
                      }
                  }
              },
              500: {
                  "description": "Internal server error",
                  "content": {
                      "application/json": {
                          "example": {"detail": ErrorResponses.SERVER_ERROR}
                      }
                  }
              }
          })
async def create_project(project_data: ProjectCreate, user: User = Depends(verify_admin)):
    try:
        # Validate project data
        if not project_data.name or not project_data.description:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorResponses.INVALID_DATA
            )

        # Generate UUID
        project_id = str(uuid.uuid4())

        # Create and save project
        project = Project(
            _id=project_id,
            name=project_data.name,
            description=project_data.description,
            created_by=user.username
        )
        project.save()

        # Return using _id instead of id
        return ProjectResponse(
            id=project._id,  # Use _id here
            name=project.name,
            description=project.description,
            created_at=project.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating project: {str(e)}")  # Add logging for debugging
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponses.SERVER_ERROR
        )


@app.put("/projects/{project_id}", response_model=ProjectResponse,
         responses={
             200: {
                 "description": "Project updated successfully",
                 "content": {"application/json": {
                     "example": {
                         "id": "507f1f77bcf86cd799439011",
                         "name": "Updated Project",
                         "description": "Updated description",
                         "created_at": "2024-01-09T10:00:00"
                     }
                 }}
             },
             400: {
                 "description": ErrorResponses.INVALID_DATA,
                 "content": {"application/json": {
                     "example": {"detail": ErrorResponses.INVALID_DATA}
                 }}
             },
             401: {
                 "description": ErrorResponses.NOT_AUTHENTICATED,
                 "content": {"application/json": {
                     "example": {"detail": ErrorResponses.NOT_AUTHENTICATED}
                 }}
             },
             403: {
                 "description": "Access forbidden",
                 "content": {"application/json": {
                     "examples": {
                         "not_admin": {
                             "summary": "User not admin",
                             "value": {"detail": ErrorResponses.NOT_ADMIN}
                         },
                         "not_creator": {
                             "summary": "Not project creator",
                             "value": {"detail": ErrorResponses.NOT_CREATOR}
                         }
                     }
                 }}
             },
             404: {
                 "description": ErrorResponses.PROJECT_NOT_FOUND,
                 "content": {"application/json": {
                     "example": {"detail": ErrorResponses.PROJECT_NOT_FOUND}
                 }}
             },
             500: {
                 "description": "Internal server error",
                 "content": {
                     "application/json": {
                         "example": {"detail": ErrorResponses.SERVER_ERROR}
                     }
                 }
             }
         })
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
                detail=ErrorResponses.INVALID_DATA
            )

        # Find and validate project
        project = Project.objects(_id=project_id).first()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponses.PROJECT_NOT_FOUND
            )

        # Verify Admin Status
        if user.role != UserRole.ADMIN.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponses.NOT_ADMIN
            )

        # Verify creator permissions
        if project.created_by != user.username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponses.NOT_CREATOR
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
            detail=ErrorResponses.SERVER_ERROR
        )


@app.patch("/projects/{project_id}", response_model=ProjectResponse,
           responses={
               200: {
                   "description": "Project updated successfully",
                   "content": {"application/json": {
                       "example": {
                           "id": "507f1f77bcf86cd799439011",
                           "name": "Updated Project",
                           "description": "Updated description",
                           "created_at": "2024-01-09T10:00:00"
                       }
                   }}
               },
               400: {
                   "description": ErrorResponses.INVALID_DATA,
                   "content": {"application/json": {
                       "example": {"detail": ErrorResponses.INVALID_DATA}
                   }}
               },
               401: {
                   "description": ErrorResponses.NOT_AUTHENTICATED,
                   "content": {"application/json": {
                       "example": {"detail": ErrorResponses.NOT_AUTHENTICATED}
                   }}
               },
               403: {
                   "description": "Access forbidden",
                   "content": {"application/json": {
                       "examples": {
                           "not_admin": {
                               "summary": "User not admin",
                               "value": {"detail": ErrorResponses.NOT_ADMIN}
                           },
                           "not_creator": {
                               "summary": "Not project creator",
                               "value": {"detail": ErrorResponses.NOT_CREATOR}
                           }
                       }
                   }}
               },
               404: {
                   "description": ErrorResponses.PROJECT_NOT_FOUND,
                   "content": {"application/json": {
                       "example": {"detail": ErrorResponses.PROJECT_NOT_FOUND}}
                   }
               },
               500: {
                   "description": "Internal server error",
                   "content": {
                       "application/json": {
                           "example": {"detail": ErrorResponses.SERVER_ERROR}
                       }
                   }
               }
           })
async def partial_update_project(
        project_id: str,
        project_data: ProjectCreate,
        user: User = Depends(verify_admin)
):
    """
    Partially update an existing project (admin only).

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
        project = Project.objects(_id=project_id).first()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponses.PROJECT_NOT_FOUND
            )

        if user.role != UserRole.ADMIN.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponses.NOT_ADMIN
            )

        if project.created_by != user.username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponses.NOT_CREATOR
            )

        if project_data.name:
            project.name = project_data.name
        if project_data.description:
            project.description = project_data.description

        project.save()

        return ProjectResponse(
            id=str(project._id),
            name=project.name,
            description=project.description,
            created_at=project.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponses.SERVER_ERROR
        )


@app.delete("/projects/{project_id}",
            responses={
                200: {
                    "description": "Project deleted successfully",
                    "content": {
                        "application/json": {
                            "example": {"message": "Project deleted successfully"}
                        }
                    }
                },
                401: {
                    "description": "Unauthorized access",
                    "content": {
                        "application/json": {
                            "example": {"detail": ErrorResponses.INSUFFICIENT_PERMISSIONS}
                        }
                    }
                },
                403: {
                    "description": "Forbidden - Not an admin",
                    "content": {
                        "application/json": {
                            "example": {"detail": ErrorResponses.NOT_ADMIN}
                        }
                    }
                },
                404: {
                    "description": "Project not found",
                    "content": {
                        "application/json": {
                            "example": {"detail": ErrorResponses.PROJECT_NOT_FOUND}
                        }
                    }
                },
                500: {
                    "description": "Internal server error",
                    "content": {
                        "application/json": {
                            "example": {"detail": ErrorResponses.SERVER_ERROR}
                        }
                    }
                }
            })
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
        project = Project.objects(_id=project_id).first()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponses.PROJECT_NOT_FOUND
            )

        # Delete project
        project.delete()
        return {"message": "Project deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponses.SERVER_ERROR
        )


# Main entry point
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
