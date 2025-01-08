# FastAPI JWT Authentication and RBAC API

This project implements a RESTful API using FastAPI with JWT authentication and Role-Based Access Control (RBAC). The API manages users with different roles and restricts access to certain endpoints based on the user's role.

## Features

- User registration and login with JWT authentication
- Role-based access control (RBAC) with admin and user roles
- Password hashing using bcrypt
- MongoDB integration using MongoEngine
- CRUD operations for projects with role-based permissions
- Ready for AWS Lambda deployment

## Prerequisites

- Python 3.8+
- MongoDB
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone [<repository-url>](https://github.com/i-sayankh/FastAPIAssignment)
cd FastAPIAssignment
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with the following content:
```
MONGODB_URL=mongodb://localhost:27017/fastapi_jwt
SECRET_KEY=your-secret-key-here
```

## Running the Application

1. Start the FastAPI application:
```bash
uvicorn app.main:app --reload
```

2. Access the API documentation at `http://localhost:8000/docs`

## API Endpoints

### Authentication
- `POST /register` - Register a new user
- `POST /login` - Login and receive JWT token

### Projects
- `GET /projects` - Get all projects (authenticated users)
- `POST /projects` - Create a new project (admin only)
- `PUT /projects/{project_id}` - Update a project (admin only)
- `DELETE /projects/{project_id}` - Delete a project (admin only)

## AWS Lambda Deployment

1. Install AWS CLI and configure your credentials.

2. Create a Lambda function:
```bash
# Package the application
pip install mangum
zip -r function.zip .

# Create Lambda function using AWS CLI
aws lambda create-function \
    --function-name fastapi-jwt-rbac \
    --runtime python3.8 \
    --handler app.main.handler \
    --role <your-lambda-role-arn> \
    --zip-file fileb://function.zip
```

3. Create an API Gateway:
- Create a new REST API
- Create a proxy integration with your Lambda function
- Deploy the API to a stage

4. Update the environment variables in Lambda:
- Set `MONGODB_URL` to your MongoDB connection string
- Set `SECRET_KEY` to your secret key

## Testing

To test the API:

1. Register a user:
```bash
curl -X POST "http://localhost:8000/register" \
     -H "Content-Type: application/json" \
     -d '{"username": "testuser", "password": "password123", "role": "user"}'
```

2. Login to get JWT token:
```bash
curl -X POST "http://localhost:8000/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "testuser", "password": "password123"}'
```

3. Use the JWT token for authenticated requests:
```bash
curl -X GET "http://localhost:8000/projects" \
     -H "Authorization: Bearer <your-jwt-token>"
```

## Security Considerations

- Keep your `SECRET_KEY` secure and never commit it to version control
- Use strong passwords and implement password policies
- Consider implementing rate limiting
- Use HTTPS in production
- Regularly update dependencies
- Monitor API usage and implement logging

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
