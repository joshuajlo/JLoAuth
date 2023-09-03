import os, logging

def genKey(length=64):
    characters='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+/<>?'
    secretKey = ''.join([os.urandom(1).hex() for _ in range(length)])
    return secretKey

strongKey = genKey()
