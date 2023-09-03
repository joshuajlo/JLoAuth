# JLoAuth

JLoAuth is a robust authentication API developed with Flask, SQLAlchemy, and Flask-JWT-Extended. It provides secure user registration, login, password reset, and token-based authentication. Use it as a foundation to enhance the security of your web applications.

## Key Features

- User registration with password hashing.
- Secure user login and token-based authentication.
- Password reset with email confirmation.
- Utilizes SQLite for efficient user data storage.
- Well-structured Flask project layout.
- Implements JWT-based access control for protected routes.

## Tech Stack

- Python
- Flask
- SQLAlchemy
- Flask-JWT-Extended
- Flask-Mail
- Bcrypt

## Deployment

To run JLoAuth locally, follow these steps:

1. Clone the repository to your local environment:

   ```bash
   git clone https://github.com/joshuajlo/JLoAuth.git
   ```

2. Create a virtual environment and activate it:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use: venv\Scripts\activate
   ```

3. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Configure your environment variables. Rename `.env.example` to `.env` and update the values as needed.

5. Launch the Flask development server:

   ```bash
   python app.py
   ```

Your JLoAuth API should now be running locally.

## License

JLoAuth is open-source and licensed under the MIT License. See the [LICENSE](https://github.com/joshuajlo/JLoAuth/blob/main/LICENSE) file for details.
