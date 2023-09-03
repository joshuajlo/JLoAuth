import unittest
from flask import Flask
from app import app, db, User

class TestUserRegistration(unittest.TestCase):

    def setUp(self):
        app.config['Testing'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()


    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()


    def test_successful_registration(self):
        response = self.app.post('/register',json={'username':'user123','email':'user@123.com','password':'pass123'})
        print(response.data)
        self.assertEqual(response.status_code,201)
        self.assertIn(b'User Registered Successfully',response.data)

if __name__ == '__main__':
    unittest.main()


