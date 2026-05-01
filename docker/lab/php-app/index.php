<?php
/**
 * TechShop - SQL Injection Testing Lab (PHP)
 *
 * DELIBERATELY VULNERABLE — Security testing only. Do NOT deploy in production.
 *
 * Vulnerabilities included:
 *   PYTHIA-SQL-001  Error-based SQLi         /index.php?page=product&id=1
 *   PYTHIA-SQL-010  Boolean blind SQLi       /index.php?page=search&q=laptop
 *   PYTHIA-SQL-010  Boolean blind SQLi       /index.php?page=reviews&product_id=1
 *   PYTHIA-SQL-010  Auth bypass SQLi         /index.php?page=login (POST)
 *   PYTHIA-SQL-030  UNION-based SQLi         /index.php?page=user&id=1
 *   PYTHIA-SQL-040  Second-order SQLi        POST /index.php?page=register → /index.php?page=profile
 *   PYTHIA-SQL-050  ORDER BY injection       /index.php?page=catalog&sort=price&order=asc
 *   PYTHIA-SQL-001  Error-based (API)        /index.php?page=api_product&id=1
 *   PYTHIA-SQL-010  Boolean blind (API)      /index.php?page=api_search&q=laptop
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
    die('<div class="error">Database connection failed: ' . htmlspecialchars($e->getMessage()) . '</div>');
}

// =============================================================================
// ROUTING
// =============================================================================
$page = $_GET['page'] ?? 'home';

// JSON API pages — output JSON and exit
if (in_array($page, ['api_product', 'api_search', 'api_category', 'api_reviews'])) {
    handleApiPage($page, $pdo);
    exit;
}

// =============================================================================
// PAGE LOGIC
// =============================================================================
$content = '';
$title   = 'TechShop';

switch ($page) {
    case 'home':     $content = renderHome($pdo);     break;
    case 'catalog':  $content = renderCatalog($pdo);  break;
    case 'product':  $content = renderProduct($pdo);  break;
    case 'search':   $content = renderSearch($pdo);   break;
    case 'reviews':  $content = renderReviews($pdo);  break;
    case 'login':    $content = renderLogin($pdo);    break;
    case 'register': $content = renderRegister($pdo); break;
    case 'profile':  $content = renderProfile($pdo);  break;
    case 'user':     $content = renderUserAdmin($pdo);break;
    default:         $content = renderHome($pdo);
}

// =============================================================================
// API HANDLERS (JSON responses — vulnerable endpoints for AJAX/fetch testing)
// =============================================================================

function handleApiPage($page, $pdo) {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');

    try {
        switch ($page) {
            case 'api_product':
                $id = $_GET['id'] ?? '1';
                // VULNERABLE: Direct concatenation
                $sql = "SELECT id, name, price, description, rating, sku FROM products WHERE id = $id";
                $stmt = $pdo->query($sql);
                echo json_encode(['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
                break;

            case 'api_search':
                $q = $_GET['q'] ?? '';
                // VULNERABLE: LIKE injection
                $sql = "SELECT id, name, price, rating FROM products WHERE name LIKE '%$q%' OR description LIKE '%$q%' LIMIT 10";
                $stmt = $pdo->query($sql);
                echo json_encode(['results' => $stmt->fetchAll(PDO::FETCH_ASSOC), 'query' => $q]);
                break;

            case 'api_category':
                $cat = $_GET['slug'] ?? '';
                // VULNERABLE: Direct concatenation
                $sql = "SELECT p.id, p.name, p.price, p.rating FROM products p
                        JOIN categories c ON p.category_id = c.id
                        WHERE c.slug = '$cat'";
                $stmt = $pdo->query($sql);
                echo json_encode(['products' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
                break;

            case 'api_reviews':
                $pid = $_GET['product_id'] ?? '1';
                // VULNERABLE: Direct concatenation
                $sql = "SELECT author, rating, comment, created_at FROM reviews WHERE product_id = $pid ORDER BY created_at DESC";
                $stmt = $pdo->query($sql);
                echo json_encode(['reviews' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
                break;
        }
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);  // VULNERABLE: SQL error exposed in JSON
    }
}

// =============================================================================
// PAGE RENDERERS
// =============================================================================

function renderHome($pdo) {
    $html = '';
    try {
        // Featured products (safe query)
        $stmt = $pdo->query("SELECT id, name, price, rating FROM products ORDER BY rating DESC LIMIT 6");
        $featured = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $html .= '<section class="hero">';
        $html .= '<h2>Welcome to TechShop</h2>';
        $html .= '<p>Your premier destination for tech products. Built for security testing.</p>';
        $html .= '<div class="hero-search">';
        $html .= '<input type="text" id="hero-search-input" placeholder="Search products..." autocomplete="off">';
        $html .= '<button onclick="doHeroSearch()">Search</button>';
        $html .= '<div id="search-suggestions" class="suggestions-box"></div>';
        $html .= '</div></section>';

        $html .= '<h3 class="section-title">Featured Products</h3>';
        $html .= '<div class="product-grid">';
        foreach ($featured as $p) {
            $stars = str_repeat('★', (int)round($p['rating'])) . str_repeat('☆', 5 - (int)round($p['rating']));
            $html .= '<div class="product-card">';
            $html .= '<div class="product-img">📦</div>';
            $html .= '<h4><a href="?page=product&id=' . $p['id'] . '">' . htmlspecialchars($p['name']) . '</a></h4>';
            $html .= '<div class="stars">' . $stars . ' (' . $p['rating'] . ')</div>';
            $html .= '<div class="price">$' . number_format($p['price'], 2) . '</div>';
            $html .= '<a href="?page=product&id=' . $p['id'] . '" class="btn-primary">View Details</a>';
            $html .= '</div>';
        }
        $html .= '</div>';

        // Category quick links
        $stmt2 = $pdo->query("SELECT id, name, slug FROM categories");
        $cats = $stmt2->fetchAll(PDO::FETCH_ASSOC);
        $html .= '<h3 class="section-title">Shop by Category</h3><div class="category-grid">';
        foreach ($cats as $c) {
            $icons = ['electronics' => '💻', 'accessories' => '🔌', 'gaming' => '🎮', 'office' => '🖥️', 'storage' => '💾'];
            $icon = $icons[$c['slug']] ?? '📦';
            $html .= '<a href="?page=catalog&category=' . urlencode($c['slug']) . '" class="category-card">';
            $html .= '<div class="cat-icon">' . $icon . '</div>';
            $html .= '<div>' . htmlspecialchars($c['name']) . '</div>';
            $html .= '</a>';
        }
        $html .= '</div>';

    } catch (PDOException $e) {
        $html .= '<div class="error">Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }
    return $html;
}

function renderCatalog($pdo) {
    $category = $_GET['category'] ?? '';
    $sort     = $_GET['sort'] ?? 'name';
    $order    = strtoupper($_GET['order'] ?? 'ASC') === 'DESC' ? 'DESC' : 'ASC';

    $html  = '<h2>Product Catalog</h2>';

    // Sort controls
    $html .= '<div class="sort-bar">';
    $html .= '<span>Sort by: </span>';
    $sorts = ['name' => 'Name', 'price' => 'Price', 'rating' => 'Rating', 'stock' => 'Stock', 'created_at' => 'Newest'];
    foreach ($sorts as $key => $label) {
        $active = $sort === $key ? 'active' : '';
        $newOrder = ($sort === $key && $order === 'ASC') ? 'DESC' : 'ASC';
        $arrow = ($sort === $key) ? ($order === 'ASC' ? ' ↑' : ' ↓') : '';
        $catParam = $category ? '&category=' . urlencode($category) : '';
        $html .= "<a href='?page=catalog{$catParam}&sort={$key}&order={$newOrder}' class='sort-link {$active}'>{$label}{$arrow}</a>";
    }
    $html .= '</div>';

    try {
        if ($category) {
            // VULNERABLE: $category directly concatenated AND $sort used in ORDER BY (PYTHIA-SQL-050)
            $sql = "SELECT p.id, p.name, p.price, p.rating, p.stock, c.name AS category_name
                    FROM products p JOIN categories c ON p.category_id = c.id
                    WHERE c.slug = '$category'
                    ORDER BY $sort $order";
        } else {
            // VULNERABLE: $sort directly in ORDER BY (PYTHIA-SQL-050)
            $sql = "SELECT p.id, p.name, p.price, p.rating, p.stock, c.name AS category_name
                    FROM products p JOIN categories c ON p.category_id = c.id
                    ORDER BY $sort $order";
        }

        $stmt = $pdo->query($sql);
        $products = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $html .= '<div class="product-grid">';
        foreach ($products as $p) {
            $stars = str_repeat('★', (int)round($p['rating'])) . str_repeat('☆', 5 - (int)round($p['rating']));
            $stockClass = $p['stock'] < 20 ? 'low-stock' : '';
            $html .= '<div class="product-card">';
            $html .= '<div class="product-img">📦</div>';
            $html .= '<div class="product-meta">' . htmlspecialchars($p['category_name']) . '</div>';
            $html .= '<h4><a href="?page=product&id=' . $p['id'] . '">' . htmlspecialchars($p['name']) . '</a></h4>';
            $html .= '<div class="stars">' . $stars . ' (' . $p['rating'] . ')</div>';
            $html .= '<div class="price">$' . number_format($p['price'], 2) . '</div>';
            if ($p['stock'] < 20) {
                $html .= '<div class="badge-low-stock">Only ' . $p['stock'] . ' left!</div>';
            }
            $html .= '<a href="?page=product&id=' . $p['id'] . '" class="btn-primary">View Details</a>';
            $html .= '</div>';
        }
        $html .= '</div>';

    } catch (PDOException $e) {
        // VULNERABLE: SQL error exposed
        $html .= '<div class="error">SQL Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }

    return $html;
}

function renderProduct($pdo) {
    $id = $_GET['id'] ?? '1';

    $html = '<h2>Product Details</h2>';

    try {
        // VULNERABLE: Direct concatenation — PYTHIA-SQL-001
        $sql = "SELECT p.*, c.name AS category_name FROM products p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.id = $id";
        $stmt  = $pdo->query($sql);
        $product = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($product) {
            $stars = str_repeat('★', (int)round($product['rating'])) . str_repeat('☆', 5 - (int)round($product['rating']));
            $html .= '<div class="product-detail">';
            $html .= '<div class="product-detail-img">📦</div>';
            $html .= '<div class="product-detail-info">';
            $html .= '<span class="badge-cat">' . htmlspecialchars($product['category_name']) . '</span>';
            $html .= '<h3>' . htmlspecialchars($product['name']) . '</h3>';
            $html .= '<div class="stars large">' . $stars . ' ' . $product['rating'] . '/5.0</div>';
            $html .= '<div class="price large">$' . number_format($product['price'], 2) . '</div>';
            $html .= '<p>' . htmlspecialchars($product['description']) . '</p>';
            $html .= '<div class="product-meta">SKU: ' . htmlspecialchars($product['sku']) . ' | Stock: ' . $product['stock'] . ' units</div>';
            $html .= '<button class="btn-primary btn-large" onclick="addToCart(' . $product['id'] . ')">Add to Cart</button>';
            $html .= '</div></div>';

            // Reviews section (loads via JS fetch — also vulnerable API)
            $html .= '<div class="reviews-section">';
            $html .= '<h3>Customer Reviews <span id="review-count"></span></h3>';
            $html .= '<div id="reviews-container"><div class="loading">Loading reviews...</div></div>';
            $html .= '</div>';
            $html .= '<script>loadReviews(' . (int)$product['id'] . ');</script>';

        } else {
            $html .= '<div class="error">Product not found with ID: ' . htmlspecialchars($id) . '</div>';
        }

    } catch (PDOException $e) {
        // VULNERABLE: Exposes SQL error with DBMS version
        $html .= '<div class="error">SQL Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }

    return $html;
}

function renderSearch($pdo) {
    $q      = $_GET['q'] ?? '';
    $minPrice = (float)($_GET['min_price'] ?? 0);
    $maxPrice = (float)($_GET['max_price'] ?? 9999);

    $html  = '<h2>Search Products</h2>';
    $html .= '<div class="search-box">';
    $html .= '<form method="GET">';
    $html .= '<input type="hidden" name="page" value="search">';
    $html .= '<input type="search" name="q" placeholder="Search products..." value="' . htmlspecialchars($q) . '" id="main-search" autocomplete="off">';
    $html .= '<div id="search-suggestions" class="suggestions-box"></div>';
    $html .= '<button type="submit">Search</button>';
    $html .= '<div class="price-filter">';
    $html .= '<label>Price: $<input type="number" name="min_price" value="' . $minPrice . '" style="width:80px"> — $<input type="number" name="max_price" value="' . ($maxPrice >= 9999 ? '' : $maxPrice) . '" style="width:80px"></label>';
    $html .= '</div></form></div>';

    if ($q !== '') {
        try {
            // VULNERABLE: $q directly concatenated — PYTHIA-SQL-010
            $sql = "SELECT p.id, p.name, p.price, p.rating, p.description, c.name AS cat
                    FROM products p LEFT JOIN categories c ON p.category_id = c.id
                    WHERE (p.name LIKE '%$q%' OR p.description LIKE '%$q%')
                    AND p.price BETWEEN $minPrice AND $maxPrice";

            $stmt   = $pdo->query($sql);
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if ($results) {
                $html .= '<p class="result-count">Found <strong>' . count($results) . '</strong> results for "<em>' . htmlspecialchars($q) . '</em>"</p>';
                $html .= '<div class="product-grid">';
                foreach ($results as $p) {
                    $stars = str_repeat('★', (int)round($p['rating'])) . str_repeat('☆', 5 - (int)round($p['rating']));
                    $html .= '<div class="product-card">';
                    $html .= '<div class="product-img">📦</div>';
                    $html .= '<div class="product-meta">' . htmlspecialchars($p['cat']) . '</div>';
                    $html .= '<h4><a href="?page=product&id=' . $p['id'] . '">' . htmlspecialchars($p['name']) . '</a></h4>';
                    $html .= '<div class="stars">' . $stars . '</div>';
                    $html .= '<div class="price">$' . number_format($p['price'], 2) . '</div>';
                    $html .= '<a href="?page=product&id=' . $p['id'] . '" class="btn-primary">View</a>';
                    $html .= '</div>';
                }
                $html .= '</div>';
            } else {
                $html .= '<div class="no-results"><p>No products found for "<strong>' . htmlspecialchars($q) . '</strong>"</p><p>Try a different search term.</p></div>';
            }
        } catch (PDOException $e) {
            $html .= '<div class="error">Search Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
    }

    return $html;
}

function renderReviews($pdo) {
    $productId = $_GET['product_id'] ?? '1';
    $minRating = $_GET['min_rating'] ?? '1';

    $html = '<h2>Product Reviews</h2>';
    $html .= '<div class="review-filter">';
    $html .= '<form method="GET">';
    $html .= '<input type="hidden" name="page" value="reviews">';
    $html .= '<input type="hidden" name="product_id" value="' . htmlspecialchars($productId) . '">';
    $html .= '<label>Minimum rating: ';
    $html .= '<select name="min_rating">';
    for ($i = 1; $i <= 5; $i++) {
        $sel = $minRating == $i ? 'selected' : '';
        $html .= "<option value='$i' $sel>$i ★</option>";
    }
    $html .= '</select></label> <button type="submit">Filter</button></form></div>';

    try {
        // VULNERABLE: $productId and $minRating directly concatenated
        $sql = "SELECT r.author, r.rating, r.comment, r.created_at, p.name AS product_name
                FROM reviews r JOIN products p ON r.product_id = p.id
                WHERE r.product_id = $productId AND r.rating >= $minRating
                ORDER BY r.created_at DESC";

        $stmt  = $pdo->query($sql);
        $reviews = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($reviews) {
            $html .= '<h3>' . htmlspecialchars($reviews[0]['product_name']) . ' — Reviews</h3>';
            foreach ($reviews as $r) {
                $stars = str_repeat('★', $r['rating']) . str_repeat('☆', 5 - $r['rating']);
                $html .= '<div class="review-card">';
                $html .= '<div class="review-header"><strong>' . htmlspecialchars($r['author']) . '</strong> <span class="stars">' . $stars . '</span></div>';
                $html .= '<p>' . htmlspecialchars($r['comment']) . '</p>';
                $html .= '<div class="review-date">' . $r['created_at'] . '</div>';
                $html .= '</div>';
            }
        } else {
            $html .= '<p>No reviews matching your criteria.</p>';
        }
    } catch (PDOException $e) {
        $html .= '<div class="error">SQL Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }

    return $html;
}

function renderLogin($pdo) {
    $html  = '<h2>Account Login</h2>';
    $error = '';
    $success = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];

        // VULNERABLE: Direct concatenation — authentication bypass possible
        $sql = "SELECT id, username, email, role FROM users WHERE username = '$username' AND password = '$password'";

        try {
            $stmt = $pdo->query($sql);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $success = '<div class="success-box"><h3>✓ Login Successful!</h3><p>Welcome back, <strong>' . htmlspecialchars($user['username']) . '</strong>!</p><p>Role: <span class="badge-role">' . htmlspecialchars($user['role']) . '</span></p><p>Email: ' . htmlspecialchars($user['email']) . '</p></div>';
            } else {
                $error = 'Invalid username or password.';
            }
        } catch (PDOException $e) {
            $error = 'Login error: ' . $e->getMessage();
        }
    }

    $html .= $success;
    if ($error) $html .= '<div class="error">' . htmlspecialchars($error) . '</div>';

    $html .= '<div class="form-container"><form method="POST" action="?page=login">';
    $html .= '<div class="form-group"><label>Username</label><input type="text" name="username" placeholder="Enter username" autocomplete="username" required></div>';
    $html .= '<div class="form-group"><label>Password</label><input type="password" name="password" placeholder="Enter password" autocomplete="current-password" required></div>';
    $html .= '<button type="submit" class="btn-primary btn-block">Sign In</button>';
    $html .= '</form>';
    $html .= '<p class="form-hint">Don\'t have an account? <a href="?page=register">Register here</a></p>';
    $html .= '<div class="hint-box"><strong>Test accounts:</strong><br>admin / admin123 (administrator)<br>john.doe / john123 (user)</div>';
    $html .= '</div>';

    return $html;
}

function renderRegister($pdo) {
    $html    = '<h2>Create Account</h2>';
    $success = '';
    $error   = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
        $username = $_POST['username'];
        $email    = $_POST['email'] ?? '';
        $bio      = $_POST['bio'] ?? '';

        try {
            // VULNERABLE: Stores raw $username directly — second-order SQLi!
            // When profile page retrieves this username and uses it in a query,
            // the stored SQL payload executes.
            $stmt = $pdo->prepare("INSERT INTO user_profiles (username, bio) VALUES (?, ?)");
            $stmt->execute([$username, $bio]);
            $success = '<div class="success-box">✓ Account created! <a href="?page=profile&username=' . urlencode($username) . '">View your profile</a></div>';
        } catch (PDOException $e) {
            $error = 'Registration error: ' . $e->getMessage();
        }
    }

    $html .= $success;
    if ($error) $html .= '<div class="error">' . htmlspecialchars($error) . '</div>';

    $html .= '<div class="form-container"><form method="POST" action="?page=register">';
    $html .= '<div class="form-group"><label>Username *</label><input type="text" name="username" placeholder="Choose a username" required></div>';
    $html .= '<div class="form-group"><label>Email</label><input type="email" name="email" placeholder="your@email.com"></div>';
    $html .= '<div class="form-group"><label>Bio</label><textarea name="bio" placeholder="Tell us about yourself..." rows="3" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;"></textarea></div>';
    $html .= '<button type="submit" class="btn-primary btn-block">Create Account</button>';
    $html .= '</form>';
    $html .= '<div class="hint-box"><strong>Security Lab Note:</strong> Try registering with username: <code>test\'sqli</code> or <code>admin\'-- </code> then view your profile to trigger second-order SQL injection.</div>';
    $html .= '</div>';

    return $html;
}

function renderProfile($pdo) {
    $username = $_GET['username'] ?? '';
    $html = '<h2>User Profile</h2>';

    if (!$username) {
        $html .= '<p>No username provided. <a href="?page=register">Register here</a>.</p>';
        return $html;
    }

    try {
        // Step 1: Retrieve stored username (safe parameterized query)
        $stmt = $pdo->prepare("SELECT id, username, bio, registered_at FROM user_profiles WHERE username = ?");
        $stmt->execute([$username]);
        $profile = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$profile) {
            $html .= '<div class="error">Profile not found for: ' . htmlspecialchars($username) . '</div>';
            return $html;
        }

        // Step 2: Use the stored username in ANOTHER query — SECOND ORDER SQLi!
        // The stored username might contain SQL payloads that execute here.
        $storedUsername = $profile['username'];  // this is the RAW value from DB
        $sql = "SELECT id, username, email, role, created_at FROM users WHERE username = '$storedUsername'";
        $stmt2 = $pdo->query($sql);
        $shopUser = $stmt2->fetch(PDO::FETCH_ASSOC);

        $html .= '<div class="profile-card">';
        $html .= '<div class="profile-avatar">👤</div>';
        $html .= '<h3>' . htmlspecialchars($profile['username']) . '</h3>';
        if ($profile['bio']) {
            $html .= '<p class="profile-bio">' . htmlspecialchars($profile['bio']) . '</p>';
        }
        $html .= '<div class="profile-meta">Registered: ' . $profile['registered_at'] . '</div>';

        if ($shopUser) {
            $html .= '<div class="profile-shop-data"><strong>Shop Account:</strong> ' . htmlspecialchars($shopUser['email']) . ' (Role: ' . htmlspecialchars($shopUser['role']) . ')</div>';
        }
        $html .= '</div>';

    } catch (PDOException $e) {
        // VULNERABLE: SQL error from second-order payload exposed here
        $html .= '<div class="error">SQL Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }

    return $html;
}

function renderUserAdmin($pdo) {
    $id   = $_GET['id'] ?? '';
    $html = '<h2>User Administration</h2>';

    if ($id !== '') {
        try {
            // VULNERABLE: UNION-based SQLi — PYTHIA-SQL-030
            $sql = "SELECT id, username, email, role, created_at FROM users WHERE id = $id";
            $stmt  = $pdo->query($sql);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if ($users) {
                $html .= '<table class="data-table">';
                $html .= '<thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Joined</th></tr></thead><tbody>';
                foreach ($users as $u) {
                    $html .= '<tr>';
                    $html .= '<td>' . htmlspecialchars($u['id']) . '</td>';
                    $html .= '<td>' . htmlspecialchars($u['username']) . '</td>';
                    $html .= '<td>' . htmlspecialchars($u['email']) . '</td>';
                    $html .= '<td><span class="badge-role">' . htmlspecialchars($u['role']) . '</span></td>';
                    $html .= '<td>' . $u['created_at'] . '</td>';
                    $html .= '</tr>';
                }
                $html .= '</tbody></table>';
            } else {
                $html .= '<p>No user found with ID: ' . htmlspecialchars($id) . '</p>';
            }
        } catch (PDOException $e) {
            $html .= '<div class="error">SQL Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
    } else {
        $html .= '<div class="form-container"><p>Enter User ID to look up:</p>';
        $html .= '<form method="GET"><input type="hidden" name="page" value="user">';
        $html .= '<input type="number" name="id" placeholder="User ID" min="1"> ';
        $html .= '<button type="submit">Lookup</button></form>';
        $html .= '<p style="margin-top:15px;">Quick links: ';
        for ($i = 1; $i <= 4; $i++) {
            $html .= '<a href="?page=user&id=' . $i . '" style="margin-right:10px;">User #' . $i . '</a>';
        }
        $html .= '</p></div>';
    }

    return $html;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title) ?> — TechShop Lab</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f2f5; color: #333; line-height: 1.6; }
        .topbar { background: #1a237e; color: #fff; padding: 10px 24px; display: flex; align-items: center; justify-content: space-between; }
        .topbar .logo { font-size: 1.4rem; font-weight: 700; letter-spacing: -0.5px; }
        .topbar .logo span { color: #82b1ff; }
        .topbar nav a { color: #c5cae9; text-decoration: none; margin-left: 20px; font-size: 0.9rem; transition: color .2s; }
        .topbar nav a:hover { color: #fff; }
        .topbar-right { display: flex; align-items: center; gap: 12px; }
        .topbar-right a { color: #c5cae9; text-decoration: none; font-size: 0.85rem; }
        .subnav { background: #283593; padding: 8px 24px; display: flex; gap: 6px; flex-wrap: wrap; }
        .subnav a { color: #9fa8da; text-decoration: none; padding: 4px 12px; border-radius: 20px; font-size: 0.82rem; transition: all .2s; }
        .subnav a:hover, .subnav a.active { background: #3949ab; color: #fff; }
        .container { max-width: 1280px; margin: 0 auto; padding: 24px; }
        .warning-banner { background: #fff3e0; border-left: 4px solid #ff9800; padding: 12px 16px; margin-bottom: 20px; border-radius: 4px; font-size: 0.88rem; }
        h2 { color: #1a237e; margin-bottom: 16px; font-size: 1.6rem; }
        h3.section-title { color: #283593; margin: 24px 0 16px; font-size: 1.2rem; border-bottom: 2px solid #e3f2fd; padding-bottom: 8px; }
        .hero { background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); color: white; padding: 40px 32px; border-radius: 12px; margin-bottom: 24px; }
        .hero h2 { color: white; font-size: 2rem; margin-bottom: 8px; }
        .hero p { color: #c5cae9; margin-bottom: 20px; }
        .hero-search { position: relative; display: flex; gap: 8px; max-width: 500px; }
        .hero-search input { flex: 1; padding: 12px 16px; border: none; border-radius: 8px; font-size: 1rem; outline: none; }
        .product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 18px; margin: 16px 0; }
        .product-card { background: white; border-radius: 12px; padding: 18px; box-shadow: 0 2px 8px rgba(0,0,0,.08); transition: transform .2s, box-shadow .2s; }
        .product-card:hover { transform: translateY(-4px); box-shadow: 0 8px 24px rgba(0,0,0,.12); }
        .product-img { font-size: 3rem; text-align: center; margin-bottom: 12px; }
        .product-card h4 { font-size: 0.95rem; margin-bottom: 8px; }
        .product-card h4 a { color: #1a237e; text-decoration: none; }
        .product-card h4 a:hover { text-decoration: underline; }
        .product-meta { font-size: 0.78rem; color: #666; margin-bottom: 6px; }
        .price { font-size: 1.2rem; font-weight: 700; color: #c62828; margin: 8px 0; }
        .price.large { font-size: 1.8rem; }
        .stars { color: #ffa000; font-size: 0.85rem; }
        .stars.large { font-size: 1.1rem; }
        .category-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px; }
        .category-card { background: white; border-radius: 12px; padding: 20px; text-align: center; text-decoration: none; color: #333; box-shadow: 0 2px 8px rgba(0,0,0,.07); transition: all .2s; }
        .category-card:hover { background: #e8eaf6; transform: translateY(-2px); }
        .cat-icon { font-size: 2rem; margin-bottom: 8px; }
        .sort-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
        .sort-link { padding: 6px 14px; border-radius: 20px; background: #e8eaf6; color: #3949ab; text-decoration: none; font-size: 0.85rem; transition: all .2s; }
        .sort-link:hover, .sort-link.active { background: #3949ab; color: white; }
        .product-detail { display: grid; grid-template-columns: 200px 1fr; gap: 32px; background: white; padding: 28px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,.08); margin-bottom: 24px; }
        .product-detail-img { font-size: 8rem; text-align: center; }
        .badge-cat { background: #e3f2fd; color: #1565c0; padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; display: inline-block; margin-bottom: 8px; }
        .badge-role { background: #e8f5e9; color: #2e7d32; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; }
        .badge-low-stock { background: #ffebee; color: #c62828; font-size: 0.78rem; padding: 2px 8px; border-radius: 4px; margin: 4px 0; }
        .search-box { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,.08); margin-bottom: 20px; }
        .search-box input[type=search] { width: 400px; padding: 10px 14px; border: 2px solid #c5cae9; border-radius: 8px; font-size: 1rem; outline: none; }
        .search-box input[type=search]:focus { border-color: #3949ab; }
        .price-filter { margin-top: 12px; font-size: 0.9rem; color: #555; }
        .suggestions-box { position: absolute; top: 100%; left: 0; right: 0; background: white; border: 1px solid #ddd; border-radius: 0 0 8px 8px; z-index: 100; display: none; box-shadow: 0 4px 12px rgba(0,0,0,.15); }
        .suggestion-item { padding: 10px 14px; cursor: pointer; border-bottom: 1px solid #f0f0f0; font-size: 0.9rem; }
        .suggestion-item:hover { background: #e8eaf6; }
        .result-count { color: #555; margin-bottom: 12px; }
        .no-results { text-align: center; padding: 40px; color: #666; }
        .review-card { background: white; border-radius: 8px; padding: 16px; margin-bottom: 12px; box-shadow: 0 1px 4px rgba(0,0,0,.07); }
        .review-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
        .review-date { color: #888; font-size: 0.82rem; margin-top: 8px; }
        .review-filter { background: white; padding: 16px; border-radius: 8px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.07); }
        .reviews-section { background: #fafafa; padding: 20px; border-radius: 8px; margin-top: 20px; }
        .form-container { background: white; padding: 28px; border-radius: 12px; max-width: 480px; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; font-weight: 600; margin-bottom: 6px; font-size: 0.9rem; color: #333; }
        .form-group input { width: 100%; padding: 10px 14px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 0.95rem; outline: none; transition: border-color .2s; }
        .form-group input:focus { border-color: #3949ab; }
        .form-hint { margin-top: 16px; font-size: 0.88rem; color: #666; text-align: center; }
        .hint-box { margin-top: 20px; background: #f3f4fd; padding: 14px; border-radius: 8px; font-size: 0.85rem; color: #555; border-left: 3px solid #7986cb; }
        .hint-box code { background: white; padding: 1px 5px; border-radius: 3px; font-family: monospace; color: #c62828; }
        .success-box { background: #e8f5e9; border-left: 4px solid #4caf50; padding: 16px; border-radius: 8px; margin-bottom: 16px; }
        .profile-card { background: white; border-radius: 12px; padding: 28px; box-shadow: 0 2px 8px rgba(0,0,0,.08); text-align: center; max-width: 400px; }
        .profile-avatar { font-size: 5rem; margin-bottom: 12px; }
        .profile-bio { color: #555; margin: 8px 0; }
        .profile-meta { color: #888; font-size: 0.85rem; margin-top: 8px; }
        .profile-shop-data { margin-top: 16px; background: #f5f5f5; padding: 12px; border-radius: 8px; font-size: 0.88rem; text-align: left; }
        .data-table { width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
        .data-table th { background: #1a237e; color: white; padding: 14px 16px; text-align: left; font-size: 0.9rem; }
        .data-table td { padding: 12px 16px; border-bottom: 1px solid #f0f0f0; font-size: 0.9rem; }
        .data-table tr:hover td { background: #f8f9ff; }
        .error { color: #c62828; background: #ffebee; padding: 14px 16px; border-radius: 8px; border-left: 4px solid #c62828; margin: 12px 0; font-family: monospace; font-size: 0.9rem; white-space: pre-wrap; }
        .loading { color: #888; font-style: italic; padding: 20px; text-align: center; }
        input[type=text], input[type=password], input[type=number], input[type=email], input[type=search] { padding: 10px 14px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 0.95rem; outline: none; }
        select { padding: 8px 12px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 0.9rem; }
        button, .btn-primary { display: inline-block; background: #3949ab; color: white; padding: 10px 22px; border: none; border-radius: 8px; cursor: pointer; font-size: 0.95rem; text-decoration: none; transition: background .2s; }
        button:hover, .btn-primary:hover { background: #283593; }
        .btn-large { padding: 14px 32px; font-size: 1rem; margin-top: 12px; }
        .btn-block { width: 100%; text-align: center; padding: 12px; font-size: 1rem; }
        footer { background: #1a237e; color: #9fa8da; text-align: center; padding: 20px; font-size: 0.85rem; margin-top: 40px; }
        footer a { color: #7986cb; text-decoration: none; }
        @media (max-width: 768px) { .product-grid { grid-template-columns: 1fr 1fr; } .product-detail { grid-template-columns: 1fr; } .topbar nav { display: none; } }
    </style>
</head>
<body>

<div class="topbar">
    <div class="logo">Tech<span>Shop</span></div>
    <nav>
        <a href="?page=home">Home</a>
        <a href="?page=catalog">Catalog</a>
        <a href="?page=search">Search</a>
        <a href="?page=login">Account</a>
    </nav>
    <div class="topbar-right">
        <a href="?page=register">Register</a>
        <a href="?page=login">Login</a>
    </div>
</div>

<div class="subnav">
    <?php
    try {
        $cats = $pdo->query("SELECT name, slug FROM categories")->fetchAll(PDO::FETCH_ASSOC);
        foreach ($cats as $c) {
            $active = (($_GET['category'] ?? '') === $c['slug']) ? 'active' : '';
            echo '<a href="?page=catalog&category=' . urlencode($c['slug']) . '" class="' . $active . '">' . htmlspecialchars($c['name']) . '</a>';
        }
    } catch (Exception $e) {}
    ?>
    <a href="?page=reviews&product_id=1">Reviews</a>
    <a href="?page=user">Admin</a>
</div>

<div class="container">
    <div class="warning-banner">
        ⚠️ <strong>DELIBERATELY VULNERABLE</strong> — SQL Injection Testing Lab. For authorized security testing only. <a href="?page=home">← Home</a>
    </div>

    <?= $content ?>
</div>

<footer>
    <p><strong>TechShop SQL Injection Lab</strong> — Pythia Security Testing Platform</p>
    <p>API endpoints: <a href="?page=api_product&id=1">/api/product</a> · <a href="?page=api_search&q=laptop">/api/search</a> · <a href="?page=api_category&slug=electronics">/api/category</a> · <a href="?page=api_reviews&product_id=1">/api/reviews</a></p>
</footer>

<script>
// =============================================================================
// JavaScript — Fetch-based features (also hits vulnerable API endpoints)
// =============================================================================

// Autocomplete search (uses vulnerable /api_search endpoint)
function setupAutocomplete(inputId, suggestionsId) {
    const input = document.getElementById(inputId);
    const box   = document.getElementById(suggestionsId);
    if (!input || !box) return;

    let debounce;
    input.addEventListener('input', function () {
        clearTimeout(debounce);
        const q = this.value.trim();
        if (q.length < 2) { box.style.display = 'none'; return; }

        debounce = setTimeout(() => {
            // Fetch suggestions from vulnerable API
            fetch('?page=api_search&q=' + encodeURIComponent(q))
                .then(r => r.json())
                .then(data => {
                    if (!data.results || data.results.length === 0) {
                        box.style.display = 'none';
                        return;
                    }
                    box.innerHTML = '';
                    data.results.slice(0, 6).forEach(product => {
                        const item = document.createElement('div');
                        item.className = 'suggestion-item';
                        item.textContent = product.name + ' — $' + parseFloat(product.price).toFixed(2);
                        item.onclick = () => { window.location = '?page=product&id=' + product.id; };
                        box.appendChild(item);
                    });
                    box.style.display = 'block';
                })
                .catch(() => { box.style.display = 'none'; });
        }, 300);
    });

    document.addEventListener('click', e => {
        if (!input.contains(e.target)) box.style.display = 'none';
    });
}

setupAutocomplete('hero-search-input', 'search-suggestions');
setupAutocomplete('main-search', 'search-suggestions');

function doHeroSearch() {
    const q = document.getElementById('hero-search-input')?.value.trim();
    if (q) window.location = '?page=search&q=' + encodeURIComponent(q);
}

// Load reviews via fetch (uses vulnerable API endpoint)
function loadReviews(productId) {
    const container = document.getElementById('reviews-container');
    const countEl   = document.getElementById('review-count');
    if (!container) return;

    fetch('?page=api_reviews&product_id=' + productId)
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                container.innerHTML = '<div class="error">API Error: ' + data.error + '</div>';
                return;
            }
            const reviews = data.reviews || [];
            if (countEl) countEl.textContent = '(' + reviews.length + ')';
            if (reviews.length === 0) {
                container.innerHTML = '<p>No reviews yet. Be the first!</p>';
                return;
            }
            const stars = n => '★'.repeat(n) + '☆'.repeat(5-n);
            container.innerHTML = reviews.map(r =>
                `<div class="review-card">
                    <div class="review-header"><strong>${r.author}</strong> <span class="stars">${stars(r.rating)}</span></div>
                    <p>${r.comment}</p>
                    <div class="review-date">${r.created_at}</div>
                </div>`
            ).join('');
        })
        .catch(err => {
            container.innerHTML = '<div class="error">Failed to load reviews: ' + err + '</div>';
        });
}

// Add to cart (AJAX — hits api_product for product info)
function addToCart(productId) {
    fetch('?page=api_product&id=' + productId)
        .then(r => r.json())
        .then(data => {
            if (data.data && data.data[0]) {
                alert('Added to cart: ' + data.data[0].name);
            }
        });
}

// Category product loader
function loadCategoryProducts(slug) {
    fetch('?page=api_category&slug=' + encodeURIComponent(slug))
        .then(r => r.json())
        .then(data => {
            console.log('Category products:', data.products?.length);
        });
}
</script>

</body>
</html>
