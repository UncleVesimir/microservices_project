CREATE USER auth_user WITH ENCRYPTED PASSWORD 'Aauth123';

CREATE DATABASE auth;

GRANT ALL PRIVILEGES ON DATABASE auth TO auth_user;

\c auth

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  pword VARCHAR(255) NOT NULL
);

INSERT INTO users(email, pword) VALUES ('james@jamesjmelling.com', 'admin123');