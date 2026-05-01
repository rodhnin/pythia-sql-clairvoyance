-- ============================================================================
-- MySQL Initialization Script for Pythia SQL Injection Lab
-- ============================================================================

CREATE DATABASE IF NOT EXISTS shop;
CREATE DATABASE IF NOT EXISTS blog;
CREATE DATABASE IF NOT EXISTS dvwa;

CREATE USER IF NOT EXISTS 'shop'@'%' IDENTIFIED BY 'shop123';
CREATE USER IF NOT EXISTS 'blog'@'%' IDENTIFIED BY 'blog123';
CREATE USER IF NOT EXISTS 'dvwa'@'%' IDENTIFIED BY 'dvwa123';

GRANT ALL PRIVILEGES ON shop.* TO 'shop'@'%';
GRANT ALL PRIVILEGES ON blog.* TO 'blog'@'%';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'%';
FLUSH PRIVILEGES;

-- ============================================================================
-- SHOP DATABASE (PHP App)
-- ============================================================================
USE shop;

CREATE TABLE categories (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    category_id INT,
    description TEXT,
    stock INT DEFAULT 100,
    rating DECIMAL(3,2) DEFAULT 0.00,
    sku VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(30),
    address TEXT,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Second-order SQLi: stores raw username, retrieved unsanitized later
CREATE TABLE user_profiles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    bio TEXT,
    avatar_url VARCHAR(500),
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    product_id INT,
    quantity INT DEFAULT 1,
    total DECIMAL(10,2),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE reviews (
    id INT PRIMARY KEY AUTO_INCREMENT,
    product_id INT NOT NULL,
    user_id INT,
    author VARCHAR(100),
    rating INT CHECK (rating BETWEEN 1 AND 5),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Categories
INSERT INTO categories (name, slug, description) VALUES
('Electronics', 'electronics', 'Laptops, monitors, peripherals and more'),
('Accessories', 'accessories', 'Cables, stands, hubs and desk accessories'),
('Gaming', 'gaming', 'Gaming mice, keyboards, headsets and controllers'),
('Office', 'office', 'Chairs, lamps, organizers and office supplies'),
('Storage', 'storage', 'SSDs, HDDs, USB drives and memory cards');

-- Products (20 products with categories)
INSERT INTO products (name, price, category_id, description, stock, rating, sku) VALUES
('Laptop Pro 15"',         1299.99, 1, 'High-performance laptop with 16GB RAM, 512GB NVMe SSD, Intel i7-13th Gen', 25,  4.80, 'ELEC-001'),
('Gaming Laptop 17"',      1599.99, 1, 'RTX 4070 GPU, 32GB DDR5 RAM, 1TB SSD, 144Hz IPS display',               10,  4.70, 'ELEC-002'),
('Ultrabook 13"',           899.99, 1, 'Ultra-thin 13 inch laptop, 8GB LPDDR5, 256GB SSD, 18-hour battery',     18,  4.50, 'ELEC-003'),
('Monitor 27" 4K',          349.99, 1, '27-inch 4K IPS monitor with HDR400, 99% sRGB, USB-C 65W charging',      30,  4.60, 'ELEC-004'),
('Monitor 24" 144Hz',       219.99, 1, '24-inch Full HD 144Hz gaming monitor, 1ms response time, FreeSync',      40,  4.40, 'ELEC-005'),
('Webcam 4K',               129.99, 1, '4K 30fps webcam, autofocus, dual microphone, Windows Hello',             55,  4.30, 'ELEC-006'),
('Mechanical Keyboard RGB',  89.99, 3, 'TKL mechanical keyboard, Cherry MX Red switches, RGB backlight',         60,  4.70, 'GAME-001'),
('Gaming Mouse 16K DPI',     69.99, 3, 'Optical gaming mouse 16000 DPI, 7 programmable buttons, RGB lighting',  75,  4.60, 'GAME-002'),
('Gaming Headset 7.1',       79.99, 3, 'Surround sound gaming headset, noise-cancelling mic, USB+3.5mm',        45,  4.20, 'GAME-003'),
('Controller Pro',           59.99, 3, 'PC/PS5 compatible controller, hall effect joysticks, USB-C',            50,  4.50, 'GAME-004'),
('Wireless Mouse',           29.99, 2, 'Ergonomic wireless mouse, 2.4GHz, 18-month battery life',               120, 4.40, 'ACCS-001'),
('USB-C Hub 10-in-1',        59.99, 2, 'HDMI 4K, 2xUSB-A 3.0, 2xUSB-C, SD/microSD, Ethernet, 100W PD',        85,  4.50, 'ACCS-002'),
('Phone Stand Aluminum',     24.99, 2, 'Adjustable aluminum phone/tablet stand, 270-degree rotation',           200, 4.30, 'ACCS-003'),
('Cable Management Kit',     19.99, 2, 'Cable clips, velcro ties, cable box organizer — complete kit',           300, 4.10, 'ACCS-004'),
('External SSD 2TB',        189.99, 5, 'USB 3.2 Gen2 external SSD, 1050MB/s read, shock resistant',             35,  4.80, 'STOR-001'),
('USB Flash Drive 256GB',    24.99, 5, 'USB 3.1 flash drive, 400MB/s read, metal body, keychain cap',           250, 4.20, 'STOR-002'),
('NVMe SSD 1TB',            109.99, 5, 'PCIe 4.0 NVMe M.2 SSD, 7000MB/s sequential read, 5yr warranty',        40,  4.90, 'STOR-003'),
('LED Desk Lamp',            39.99, 4, 'Adjustable LED desk lamp, 5 color temps, USB charging port, touch ctrl', 90, 4.30, 'OFFC-001'),
('Ergonomic Wrist Rest',     22.99, 4, 'Memory foam wrist rest for keyboard and mouse, non-slip base',           150, 4.20, 'OFFC-002'),
('Laptop Cooling Pad',       34.99, 4, 'Laptop cooling pad with 2 fans, RGB, adjustable height, USB powered',    70, 4.40, 'OFFC-003');

-- Users (with PII for contextual risk scoring tests)
INSERT INTO users (username, password, email, phone, address, role) VALUES
('admin',    'admin123',   'admin@techshop.local',   '+1-555-0100', '100 Admin St, Server Room, CA 94102',    'administrator'),
('john.doe', 'john123',    'john.doe@gmail.com',     '+1-555-0101', '123 Main St, San Francisco, CA 94105',   'user'),
('alice',    'alice123',   'alice.smith@hotmail.com','+1-555-0102', '456 Oak Ave, Oakland, CA 94601',         'user'),
('bob',      'bob123',     'bob.jones@yahoo.com',    '+1-555-0103', '789 Pine Rd, Berkeley, CA 94710',        'user'),
('charlie',  'charlie123', 'charlie@work.co',        '+1-555-0104', '321 Elm St, Palo Alto, CA 94301',        'moderator'),
('diana',    'diana123',   'diana@company.org',      '+1-555-0105', '654 Maple Dr, San Jose, CA 95101',       'user'),
('eve',      'eve123',     'eve.developer@proton.me','+1-555-0106', '987 Cedar Ln, Mountain View, CA 94041',  'user'),
('mallory',  'mallory123', 'mallory@test.net',       '+1-555-0107', '147 Birch Ave, Sunnyvale, CA 94085',     'user');

-- Reviews
INSERT INTO reviews (product_id, user_id, author, rating, comment) VALUES
(1, 2, 'john.doe',  5, 'Excellent laptop! Fast and reliable. The i7 handles everything I throw at it.'),
(1, 3, 'alice',     5, 'Amazing performance for the price. Battery lasts all day.'),
(1, 4, 'bob',       4, 'Great laptop, slightly heavy but worth it for the performance.'),
(2, 5, 'charlie',   5, 'RTX 4070 is a beast! Running all games at max settings smoothly.'),
(4, 3, 'alice',     5, 'The 4K display is stunning. Colors are vibrant and accurate.'),
(7, 2, 'john.doe',  5, 'Cherry MX Red switches are buttery smooth. RGB is gorgeous.'),
(8, 5, 'charlie',   4, 'Excellent mouse, very precise tracking. Could use more buttons.'),
(15,4, 'bob',       5, 'Blazing fast SSD. Transfer speeds are insane. Fits in my pocket too.'),
(17,2, 'john.doe',  5, '7000MB/s is no joke. Boot time under 5 seconds. Best SSD upgrade ever.'),
(6, 6, 'diana',     4, 'Windows Hello works perfectly. Clear 4K video for calls.');

-- Orders (some order history)
INSERT INTO orders (user_id, product_id, quantity, total, status) VALUES
(2, 1,  1, 1299.99, 'delivered'),
(2, 11, 1, 29.99,   'delivered'),
(3, 4,  1, 349.99,  'shipped'),
(4, 7,  1, 89.99,   'delivered'),
(5, 2,  1, 1599.99, 'processing'),
(6, 18, 1, 39.99,   'delivered'),
(7, 15, 2, 379.98,  'shipped');

-- ============================================================================
-- BLOG DATABASE (Flask App)
-- ============================================================================
USE blog;

CREATE TABLE categories (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) UNIQUE
);

CREATE TABLE posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    author VARCHAR(100) NOT NULL,
    category_id INT,
    view_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    author VARCHAR(100) NOT NULL,
    email VARCHAR(255),
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id)
);

-- Second-order SQLi: registered user stored, retrieved in profile
CREATE TABLE registered_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    bio TEXT,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO categories (name, slug) VALUES
('Security',  'security'),
('Web Dev',   'webdev'),
('Databases', 'databases'),
('DevOps',    'devops'),
('Privacy',   'privacy');

INSERT INTO posts (title, content, author, category_id, view_count) VALUES
('Welcome to SecureDev Blog',
 'Welcome to our technical security blog. We cover web security, database hardening, and secure coding practices. Our team of security researchers regularly publishes findings and tutorials.',
 'Admin', 1, 1523),
('Top 10 Web Security Vulnerabilities in 2024',
 'The OWASP Top 10 continues to evolve. SQL Injection remains one of the most critical vulnerabilities. In this post we cover injection flaws, broken access control, cryptographic failures, and more. Always use parameterized queries and validate all user input.',
 'Security Team', 1, 4782),
('Introduction to SQL and Database Design',
 'SQL is a powerful language for managing relational databases. Understanding SQL fundamentals is essential for building secure applications. Learn about SELECT, INSERT, UPDATE, DELETE, and how to use JOINs effectively.',
 'Database Admin', 3, 2341),
('Secure Authentication: Best Practices for 2024',
 'Authentication is the front door of your application. Learn how to implement bcrypt for password hashing, multi-factor authentication, JWT tokens, and session management best practices.',
 'Security Team', 1, 3156),
('Understanding and Preventing SQL Injection',
 'SQL injection is a code injection technique that exploits security vulnerabilities in an application database layer. Learn how parameterized queries, prepared statements, and ORMs protect your application.',
 'Security Expert', 1, 6234),
('Docker Security: Hardening Your Containers',
 'Containers are not inherently secure. Learn how to use non-root users, read-only filesystems, security scanning, network policies, and secrets management to harden your Docker deployments.',
 'DevOps Team', 4, 1876),
('Privacy by Design: GDPR Compliance for Developers',
 'GDPR compliance is not just a legal requirement — it is good engineering. Learn data minimization, purpose limitation, consent management, and the right to erasure.',
 'Privacy Expert', 5, 2109),
('REST API Security: Authentication and Authorization',
 'APIs are the backbone of modern applications. Learn about OAuth 2.0, API keys, rate limiting, CORS policies, and input validation for REST APIs.',
 'Security Team', 2, 3421),
('PostgreSQL vs MySQL: Security Comparison',
 'Both PostgreSQL and MySQL are excellent databases. This post compares their security features: row-level security, encryption at rest, privilege systems, and audit logging.',
 'Database Admin', 3, 1654),
('Penetration Testing Methodology: A Practical Guide',
 'Professional penetration testing follows a structured methodology: reconnaissance, scanning, exploitation, post-exploitation, and reporting. Learn the tools and techniques used by security professionals.',
 'Security Expert', 1, 5432);

INSERT INTO comments (post_id, author, email, content) VALUES
(1, 'John Doe',     'john@example.com',    'Great introduction! Looking forward to more content.'),
(1, 'Jane Smith',   'jane@example.com',    'Very informative, thank you for starting this blog!'),
(2, 'Bob Johnson',  'bob@example.com',     'These OWASP tips are really helpful for my team.'),
(2, 'Alice Brown',  'alice@example.com',   'I shared this with my dev team. SQL injection is still our biggest concern.'),
(3, 'Charlie W.',   'charlie@example.com', 'Clear explanation of SQL basics. Perfect for beginners.'),
(4, 'Diana Prince', 'diana@example.com',   'The bcrypt section was exactly what I needed. Thanks!'),
(5, 'Eve Adams',    'eve@example.com',     'Best explanation of SQL injection I have read. Very thorough.'),
(5, 'Frank Miller', 'frank@example.com',   'The parameterized query examples are gold. Bookmarked!'),
(6, 'Grace Lee',    'grace@example.com',   'Docker security is often overlooked. Great post.'),
(8, 'Henry Ford',   'henry@example.com',   'OAuth 2.0 flow diagram would be a nice addition.');

-- ============================================================================
-- Verification
-- ============================================================================
SELECT 'Database initialization complete!' AS status;
SELECT COUNT(*) AS product_count   FROM shop.products;
SELECT COUNT(*) AS user_count      FROM shop.users;
SELECT COUNT(*) AS review_count    FROM shop.reviews;
SELECT COUNT(*) AS post_count      FROM blog.posts;
SELECT COUNT(*) AS comment_count   FROM blog.comments;
