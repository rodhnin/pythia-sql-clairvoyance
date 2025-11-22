<?php
/**
 * Vulnerable Shop - SQL Injection Testing Lab
 * 
 * DELIBERADAMENTE VULNERABLE
 * 
 * Vulnerabilities:
 * - Error-based SQLi (products page)
 * - Boolean blind SQLi (search page)
 * - Authentication bypass SQLi (login page)
 * - UNION-based SQLi (users page)
 */

// =============================================================================
// DATABASE CONNECTION
// =============================================================================
$host = getenv('MYSQL_HOST') ?: 'mysql';
$db   = getenv('MYSQL_DATABASE') ?: 'shop';
$user = getenv('MYSQL_USER') ?: 'shop';
$pass = getenv('MYSQL_PASSWORD') ?: 'shop123';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("<div class='error'>Database connection failed: " . htmlspecialchars($e->getMessage()) . "</div>");
}

// =============================================================================
// ROUTING
// =============================================================================
$page = isset($_GET['page']) ? $_GET['page'] : 'home';

// =============================================================================
// PAGE LOGIC
// =============================================================================
$content = '';
$title = 'Vulnerable Shop';

switch ($page) {
    case 'home':
        $content = renderHomePage();
        break;
    case 'products':
        $content = renderProductsPage($pdo);
        break;
    case 'search':
        $content = renderSearchPage($pdo);
        break;
    case 'login':
        $content = renderLoginPage($pdo);
        break;
    case 'user':
        $content = renderUsersPage($pdo);
        break;
    default:
        $content = renderHomePage();
}

// =============================================================================
// PAGE RENDERERS
// =============================================================================

function renderHomePage() {
    return '
        <h2>Welcome to Vulnerable Shop!</h2>
        <p>This application contains multiple SQL injection vulnerabilities for testing purposes.</p>
        
        <h3>Available Test Scenarios:</h3>
        <ul>
            <li><strong>Products</strong> - Error-based SQLi in product ID</li>
            <li><strong>Search</strong> - Boolean blind SQLi in search query</li>
            <li><strong>Login</strong> - Authentication bypass SQLi</li>
            <li><strong>Users</strong> - UNION-based SQLi in user listing</li>
        </ul>
        
        <div class="vulnerable-section">
            <h4>Quick Start:</h4>
            <ul>
                <li><a href="?page=products&id=1">View Product 1</a> - Try adding <code>\'</code> to trigger SQL error</li>
                <li><a href="?page=search&q=laptop">Search for "laptop"</a> - Try boolean conditions</li>
                <li><a href="?page=login">Login Page</a> - Try bypassing authentication</li>
                <li><a href="?page=user&id=1">View User 1</a> - Try UNION SELECT</li>
            </ul>
        </div>
    ';
}

function renderProductsPage($pdo) {
    $html = '<h2>Products - Error-Based SQL Injection</h2>';
    
    $html .= '
        <div class="vulnerable-section">
            <p><strong>Vulnerability:</strong> Product ID parameter is directly concatenated into SQL query.</p>
            <p><strong>Test payloads:</strong> Try: <code>?page=products&id=1\'</code> or <code>?page=products&id=1 OR 1=1</code></p>
        </div>
    ';
    
    if (isset($_GET['id'])) {
        $id = $_GET['id'];
        
        // VULNERABLE: Direct concatenation - NO PROTECTION!
        $sql = "SELECT * FROM products WHERE id = $id";
        
        try {
            $stmt = $pdo->query($sql);
            $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if ($products) {
                $html .= '<table>';
                $html .= '<tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>';
                
                foreach ($products as $product) {
                    $html .= '<tr>';
                    $html .= '<td>' . htmlspecialchars($product['id']) . '</td>';
                    $html .= '<td>' . htmlspecialchars($product['name']) . '</td>';
                    $html .= '<td>$' . htmlspecialchars($product['price']) . '</td>';
                    $html .= '<td>' . htmlspecialchars($product['description']) . '</td>';
                    $html .= '</tr>';
                }
                
                $html .= '</table>';
            } else {
                $html .= '<p>No product found with ID: ' . htmlspecialchars($id) . '</p>';
            }
        } catch (PDOException $e) {
            // VULNERABLE: Displaying SQL error messages!
            $html .= '<div class="error">SQL Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
    } else {
        $html .= '
            <form method="GET">
                <input type="hidden" name="page" value="products" />
                <input type="number" name="id" placeholder="Product ID" value="1" />
                <button type="submit">View Product</button>
            </form>
        ';
    }
    
    return $html;
}

function renderSearchPage($pdo) {
    $html = '<h2>Search - Boolean Blind SQL Injection</h2>';
    
    $html .= '
        <div class="vulnerable-section">
            <p><strong>Vulnerability:</strong> Search query is directly inserted into WHERE clause.</p>
            <p><strong>Test payloads:</strong> Try: <code>laptop\' AND \'1\'=\'1</code> vs <code>laptop\' AND \'1\'=\'0</code></p>
        </div>
    ';
    
    $html .= '
        <form method="GET">
            <input type="hidden" name="page" value="search" />
            <input type="search" name="q" placeholder="Search products..." value="' . (isset($_GET['q']) ? htmlspecialchars($_GET['q']) : '') . '" />
            <button type="submit">Search</button>
        </form>
    ';
    
    if (isset($_GET['q'])) {
        $query = $_GET['q'];
        
        // VULNERABLE: Direct concatenation in WHERE clause
        $sql = "SELECT * FROM products WHERE name LIKE '%$query%' OR description LIKE '%$query%'";
        
        try {
            $stmt = $pdo->query($sql);
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if ($results) {
                $html .= '<p>Found ' . count($results) . ' results for: <strong>' . htmlspecialchars($query) . '</strong></p>';
                
                $html .= '<table>';
                $html .= '<tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>';
                
                foreach ($results as $product) {
                    $html .= '<tr>';
                    $html .= '<td>' . htmlspecialchars($product['id']) . '</td>';
                    $html .= '<td>' . htmlspecialchars($product['name']) . '</td>';
                    $html .= '<td>$' . htmlspecialchars($product['price']) . '</td>';
                    $html .= '<td>' . htmlspecialchars($product['description']) . '</td>';
                    $html .= '</tr>';
                }
                
                $html .= '</table>';
            } else {
                $html .= '<p>No results found for: <strong>' . htmlspecialchars($query) . '</strong></p>';
            }
        } catch (PDOException $e) {
            $html .= '<div class="error">Search failed: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
    }
    
    return $html;
}

function renderLoginPage($pdo) {
    $html = '<h2>Login - Authentication Bypass SQL Injection</h2>';
    
    $html .= '
        <div class="vulnerable-section">
            <p><strong>Vulnerability:</strong> Username and password are directly concatenated into SQL query.</p>
            <p><strong>Test payloads:</strong> Username: <code>admin\'--</code> or <code>admin\' OR \'1\'=\'1</code></p>
        </div>
    ';
    
    if (isset($_POST['username']) && isset($_POST['password'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];
        
        // VULNERABLE: Direct concatenation - Authentication bypass possible!
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        
        try {
            $stmt = $pdo->query($sql);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                $html .= '
                    <div style="background: #d4edda; color: #155724; padding: 15px; border-radius: 4px; margin: 15px 0;">
                        <h3>✓ Login Successful!</h3>
                        <p>Welcome, <strong>' . htmlspecialchars($user['username']) . '</strong>!</p>
                        <p>Role: ' . htmlspecialchars($user['role']) . '</p>
                    </div>
                ';
            } else {
                $html .= '<div class="error">Login failed: Invalid credentials</div>';
            }
        } catch (PDOException $e) {
            $html .= '<div class="error">Login error: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
    }
    
    $html .= '
        <form method="POST" action="?page=login">
            <div style="margin: 15px 0;">
                <input type="text" name="username" placeholder="Username" required />
            </div>
            <div style="margin: 15px 0;">
                <input type="password" name="password" placeholder="Password" required />
            </div>
            <button type="submit">Login</button>
        </form>
        
        <div style="margin-top: 20px; color: #666; font-size: 14px;">
            <p><strong>Valid credentials:</strong> admin / admin123</p>
            <p><strong>SQLi payload:</strong> Try username: <code>admin\'--</code> with any password</p>
        </div>
    ';
    
    return $html;
}

function renderUsersPage($pdo) {
    $html = '<h2>Users - UNION-Based SQL Injection</h2>';
    
    $html .= '
        <div class="vulnerable-section">
            <p><strong>Vulnerability:</strong> User ID parameter is directly concatenated, allowing UNION SELECT.</p>
            <p><strong>Test payloads:</strong> Try: <code>?page=user&id=1 UNION SELECT 1,2,3,4,5</code></p>
        </div>
    ';
    
    if (isset($_GET['id'])) {
        $id = $_GET['id'];
        
        // VULNERABLE: Direct concatenation - UNION attacks possible!
        $sql = "SELECT id, username, email, role FROM users WHERE id = $id";
        
        try {
            $stmt = $pdo->query($sql);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if ($users) {
                $html .= '<table>';
                $html .= '<tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>';
                
                foreach ($users as $user) {
                    $html .= '<tr>';
                    $html .= '<td>' . htmlspecialchars($user['id']) . '</td>';
                    $html .= '<td>' . htmlspecialchars($user['username']) . '</td>';
                    $html .= '<td>' . htmlspecialchars($user['email']) . '</td>';
                    $html .= '<td>' . htmlspecialchars($user['role']) . '</td>';
                    $html .= '</tr>';
                }
                
                $html .= '</table>';
            } else {
                $html .= '<p>No user found with ID: ' . htmlspecialchars($id) . '</p>';
            }
        } catch (PDOException $e) {
            $html .= '<div class="error">SQL Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
    } else {
        $html .= '
            <form method="GET">
                <input type="hidden" name="page" value="user" />
                <input type="number" name="id" placeholder="User ID" value="1" />
                <button type="submit">View User</button>
            </form>
            
            <p style="margin-top: 15px;">Or view all users:</p>
            <ul>
                <li><a href="?page=user&id=1">User ID 1</a></li>
                <li><a href="?page=user&id=2">User ID 2</a></li>
                <li><a href="?page=user&id=3">User ID 3</a></li>
            </ul>
        ';
    }
    
    return $html;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($title); ?></title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #d32f2f;
            border-bottom: 3px solid #d32f2f;
            padding-bottom: 10px;
            margin-top: 0;
        }
        h2 {
            color: #1976d2;
            margin-top: 30px;
        }
        h3 {
            color: #424242;
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .vulnerable-section {
            background: #f8f9fa;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
            border-left: 4px solid #dc3545;
        }
        .vulnerable-section code {
            background: #fff;
            padding: 2px 6px;
            border-radius: 3px;
            border: 1px solid #ddd;
        }
        form {
            margin: 15px 0;
        }
        input[type="text"],
        input[type="password"],
        input[type="number"],
        input[type="search"] {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            width: 300px;
            font-size: 14px;
        }
        button {
            background: #1976d2;
            color: white;
            padding: 10px 24px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            margin-left: 10px;
        }
        button:hover {
            background: #1565c0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #1976d2;
            color: white;
            font-weight: 600;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .error {
            color: #d32f2f;
            font-weight: bold;
            background: #ffebee;
            padding: 12px;
            border-radius: 4px;
            margin: 10px 0;
            border-left: 4px solid #d32f2f;
        }
        .nav {
            background: #1976d2;
            padding: 15px;
            margin: -20px -20px 20px -20px;
            border-radius: 8px 8px 0 0;
        }
        .nav a {
            color: white;
            text-decoration: none;
            margin-right: 20px;
            font-weight: bold;
            padding: 5px 10px;
            border-radius: 3px;
            transition: background 0.3s;
        }
        .nav a:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #ddd;
            color: #666;
            font-size: 14px;
            text-align: center;
        }
        code {
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="?page=home">Home</a>
            <a href="?page=products">Products</a>
            <a href="?page=search">Search</a>
            <a href="?page=login">Login</a>
            <a href="?page=user">Users</a>
        </div>

        <h1>🛒 Vulnerable Shop - SQL Injection Testing Lab</h1>

        <div class="warning">
            ⚠️ <strong>WARNING:</strong> This is a deliberately vulnerable application for security testing purposes only. 
            Do NOT deploy this on a production server or public network!
        </div>

        <?php echo $content; ?>

        <div class="footer">
            <p><strong>Pythia SQL Injection Testing Lab - PHP Edition</strong></p>
            <p>Created for security testing purposes only. Use responsibly.</p>
        </div>
    </div>
</body>
</html>