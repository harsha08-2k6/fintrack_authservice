# Authentication & User Microservice

Handles user identity, registration, password hashing (BCrypt), and stateless JWT token authentication.

- **Port**: `8081`
- **Database**: `spendwise_auth`
- **Endpoints**:
  - `POST /api/auth/register` - Create account
  - `POST /api/auth/login` - Authenticate & get JWT
  - `GET /api/auth/me` - Authenticated user details
  - `POST /api/auth/validate` - Token verification

### Running
```bash
mvn spring-boot:run
```
