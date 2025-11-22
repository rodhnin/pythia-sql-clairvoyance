-- ============================================================================
-- MySQL Initialization Script for SQL Injection Lab
-- ============================================================================

-- Create databases
CREATE DATABASE IF NOT EXISTS shop;
CREATE DATABASE IF NOT EXISTS blog;
CREATE DATABASE IF NOT EXISTS dvwa;

-- Create users
CREATE USER IF NOT EXISTS 'shop'@'%' IDENTIFIED BY 'shop123';
CREATE USER IF NOT EXISTS 'blog'@'%' IDENTIFIED BY 'blog123';
CREATE USER IF NOT EXISTS 'dvwa'@'%' IDENTIFIED BY 'dvwa123';

-- Grant permissions
GRANT ALL PRIVILEGES ON shop.* TO 'shop'@'%';
GRANT ALL PRIVILEGES ON blog.* TO 'blog'@'%';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'%';
FLUSH PRIVILEGES;

-- ============================================================================
-- SHOP DATABASE (PHP App)
-- ============================================================================
USE shop;

-- Products table
CREATE TABLE products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Users table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample products
INSERT INTO products (name, price, description) VALUES
('Laptop Pro 15"', 1299.99, 'High-performance laptop with 16GB RAM and 512GB SSD'),
('Wireless Mouse', 29.99, 'Ergonomic wireless mouse with precision tracking'),
('Mechanical Keyboard', 89.99, 'RGB backlit mechanical keyboard with Cherry MX switches'),
('USB-C Hub', 49.99, '7-in-1 USB-C hub with HDMI, USB 3.0, and SD card reader'),
('External SSD 1TB', 149.99, 'Portable external SSD with fast transfer speeds'),
('Webcam HD', 79.99, '1080p HD webcam with auto-focus and noise cancellation'),
('Monitor 27"', 349.99, '27-inch 4K monitor with HDR support'),
('Desk Lamp LED', 39.99, 'Adjustable LED desk lamp with touch control'),
('Phone Stand', 19.99, 'Aluminum phone stand with adjustable angle'),
('Cable Organizer', 12.99, 'Cable management system for desk organization');

-- Insert sample users (password is plain text for testing purposes!)
INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@shop.local', 'administrator'),
('john', 'john123', 'john@shop.local', 'user'),
('alice', 'alice123', 'alice@shop.local', 'user'),
('bob', 'bob123', 'bob@shop.local', 'moderator');

-- ============================================================================
-- BLOG DATABASE (Flask App)
-- ============================================================================
USE blog;

-- Posts table
CREATE TABLE posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    author VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Comments table
CREATE TABLE comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    author VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id)
);

-- Insert sample posts
INSERT INTO posts (title, content, author) VALUES
('Welcome to Our Blog', 'This is our first blog post! We are excited to share content with you.', 'Admin'),
('10 Tips for Web Security', 'Security is important. Here are our top 10 tips for staying safe online.', 'Security Team'),
('Introduction to SQL', 'SQL is a powerful language for managing databases. Let us show you the basics.', 'Database Admin'),
('Best Practices for Authentication', 'Learn how to implement secure authentication in your applications.', 'Security Team'),
('Understanding SQL Injection', 'SQL injection is a serious vulnerability. Here is how it works and how to prevent it.', 'Security Expert');

-- Insert sample comments
INSERT INTO comments (post_id, author, content) VALUES
(1, 'John Doe', 'Great post! Looking forward to more content.'),
(1, 'Jane Smith', 'Very informative, thank you!'),
(2, 'Bob Johnson', 'These tips are really helpful.'),
(3, 'Alice Brown', 'Clear explanation of SQL basics.'),
(5, 'Charlie Wilson', 'Important topic, thanks for covering it!');

-- ============================================================================
-- Verification
-- ============================================================================
SELECT 'Database initialization complete!' AS status;
SELECT COUNT(*) AS product_count FROM shop.products;
SELECT COUNT(*) AS user_count FROM shop.users;
SELECT COUNT(*) AS post_count FROM blog.posts;
SELECT COUNT(*) AS comment_count FROM blog.comments;