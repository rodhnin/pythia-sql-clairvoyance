"""
Vulnerable Blog - Flask SQL Injection Testing Lab

DELIBERADAMENTE VULNERABLE - Solo para testing de seguridad
NO usar en producción!

Vulnerabilidades incluidas:
- Error-based SQLi (post detail)
- Boolean blind SQLi (search)
- Union-based SQLi (API endpoint)
- Time-based SQLi (comments)
"""

from flask import Flask, request, render_template_string
import pymysql
import os
from pathlib import Path

app = Flask(__name__)

@app.route('/.well-known/<path:filename>')
def wellknown_files(filename):
    """
    Serve consent verification files.
    Pythia verifica ownership mediante archivos en .well-known/
    """
    try:
        wellknown_dir = Path(__file__).parent / '.well-known'
        file_path = wellknown_dir / filename
        
        if file_path.exists():
            with open(file_path, 'r') as f:
                content = f.read().strip()
            return content, 200, {'Content-Type': 'text/plain'}
        else:
            return "Not Found", 404
    except Exception as e:
        return f"Error: {e}", 500

# =============================================================================
# DATABASE CONNECTION
# =============================================================================
def get_db_connection():
    """Create database connection."""
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', 'mysql'),
        user=os.getenv('MYSQL_USER', 'blog'),
        password=os.getenv('MYSQL_PASSWORD', 'blog123'),
        database=os.getenv('MYSQL_DATABASE', 'blog'),
        cursorclass=pymysql.cursors.DictCursor
    )

# =============================================================================
# HTML TEMPLATE
# =============================================================================
HTML_BASE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Blog - SQL Injection Lab</title>
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
            color: #2196f3;
            border-bottom: 3px solid #2196f3;
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
        .post {
            background: white;
            padding: 20px;
            margin: 20px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .post h3 {
            margin-top: 0;
            color: #2196f3;
        }
        .post .meta {
            color: #666;
            font-size: 14px;
            margin-bottom: 10px;
        }
        .comment {
            background: #f5f5f5;
            padding: 10px;
            margin: 10px 0 10px 20px;
            border-left: 3px solid #2196f3;
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
        input[type="text"],
        input[type="number"],
        input[type="search"] {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            width: 300px;
            font-size: 14px;
        }
        button {
            background: #2196f3;
            color: white;
            padding: 10px 24px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            margin-left: 10px;
        }
        button:hover {
            background: #1976d2;
        }
        .nav {
            background: #2196f3;
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
            <a href="/">Home</a>
            <a href="/posts">All Posts</a>
            <a href="/search">Search</a>
            <a href="/api/posts">API</a>
        </div>

        <h1>📝 Vulnerable Blog - SQL Injection Testing Lab</h1>

        <div class="warning">
            ⚠️ <strong>WARNING:</strong> This is a deliberately vulnerable Flask application for security testing.
            Do NOT deploy this on a production server!
        </div>

        {{ content|safe }}

        <div class="footer">
            <p><strong>Pythia SQL Injection Testing Lab - Flask Edition</strong></p>
            <p>Created for security testing purposes only. Use responsibly.</p>
        </div>
    </div>
</body>
</html>
"""

# =============================================================================
# ROUTES
# =============================================================================

@app.route('/')
def home():
    """Home page with vulnerability descriptions."""
    content = """
        <h2>Welcome to Vulnerable Blog!</h2>
        <p>This Flask application contains multiple SQL injection vulnerabilities for testing purposes.</p>
        
        <h3>Available Test Scenarios:</h3>
        <ul>
            <li><strong>All Posts</strong> - View all blog posts</li>
            <li><strong>Post Detail</strong> - Error-based SQLi in post ID</li>
            <li><strong>Search</strong> - Boolean blind SQLi in search query</li>
            <li><strong>API</strong> - UNION-based SQLi in API endpoint</li>
        </ul>
        
        <div class="vulnerable-section">
            <h4>Quick Start:</h4>
            <ul>
                <li><a href="/posts">View All Posts</a></li>
                <li><a href="/post/1">View Post 1</a> - Try adding <code>'</code> to trigger SQL error</li>
                <li><a href="/search?q=security">Search for "security"</a> - Try boolean conditions</li>
                <li><a href="/api/posts?author=Admin">API - Filter by author</a> - Try UNION SELECT</li>
            </ul>
        </div>
        
        <h3>Recent Posts:</h3>
    """
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, author, created_at FROM posts ORDER BY created_at DESC LIMIT 5")
        posts = cursor.fetchall()
        
        for post in posts:
            content += f"""
                <div class="post">
                    <h3><a href="/post/{post['id']}">{post['title']}</a></h3>
                    <div class="meta">By {post['author']} on {post['created_at']}</div>
                </div>
            """
        
        cursor.close()
        conn.close()
    except Exception as e:
        content += f'<div class="error">Error loading posts: {str(e)}</div>'
    
    return render_template_string(HTML_BASE, content=content)


@app.route('/posts')
def posts():
    """List all posts."""
    content = '<h2>All Blog Posts</h2>'
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, author, created_at FROM posts ORDER BY created_at DESC")
        posts = cursor.fetchall()
        
        for post in posts:
            content += f"""
                <div class="post">
                    <h3><a href="/post/{post['id']}">{post['title']}</a></h3>
                    <div class="meta">By {post['author']} on {post['created_at']}</div>
                </div>
            """
        
        cursor.close()
        conn.close()
    except Exception as e:
        content += f'<div class="error">Error loading posts: {str(e)}</div>'
    
    return render_template_string(HTML_BASE, content=content)


@app.route('/post/<post_id>')
def post_detail(post_id):
    """View post details - VULNERABLE to error-based SQLi."""
    content = '<h2>Post Details - Error-Based SQL Injection</h2>'
    
    content += """
        <div class="vulnerable-section">
            <p><strong>Vulnerability:</strong> Post ID parameter is directly concatenated into SQL query.</p>
            <p><strong>Test payloads:</strong> Try: <code>/post/1'</code> or <code>/post/1 OR 1=1</code></p>
        </div>
    """
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # VULNERABLE: Direct string concatenation - NO PROTECTION!
        sql = f"SELECT * FROM posts WHERE id = {post_id}"
        cursor.execute(sql)
        post = cursor.fetchone()
        
        if post:
            content += f"""
                <div class="post">
                    <h3>{post['title']}</h3>
                    <div class="meta">By {post['author']} on {post['created_at']}</div>
                    <p>{post['content']}</p>
                </div>
                <h3>Comments:</h3>
            """
            
            # Get comments
            cursor.execute(f"SELECT * FROM comments WHERE post_id = {post_id}")
            comments = cursor.fetchall()
            
            if comments:
                for comment in comments:
                    content += f"""
                        <div class="comment">
                            <strong>{comment['author']}</strong> said:<br>
                            {comment['content']}
                        </div>
                    """
            else:
                content += '<p>No comments yet.</p>'
        else:
            content += f'<p>No post found with ID: {post_id}</p>'
        
        cursor.close()
        conn.close()
    except Exception as e:
        # VULNERABLE: Displaying SQL error messages!
        content += f'<div class="error">SQL Error: {str(e)}</div>'
    
    return render_template_string(HTML_BASE, content=content)


@app.route('/search')
def search():
    """Search posts - VULNERABLE to boolean blind SQLi."""
    content = '<h2>Search Posts - Boolean Blind SQL Injection</h2>'
    
    content += """
        <div class="vulnerable-section">
            <p><strong>Vulnerability:</strong> Search query is directly inserted into WHERE clause.</p>
            <p><strong>Test payloads:</strong> Try: <code>?q=security' AND '1'='1</code> vs <code>?q=security' AND '1'='0</code></p>
        </div>
        
        <form method="GET" action="/search">
            <input type="search" name="q" placeholder="Search posts..." value="{}" />
            <button type="submit">Search</button>
        </form>
    """.format(request.args.get('q', ''))
    
    query = request.args.get('q', '')
    
    if query:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # VULNERABLE: Direct concatenation in WHERE clause
            sql = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
            cursor.execute(sql)
            results = cursor.fetchall()
            
            if results:
                content += f'<p>Found {len(results)} results for: <strong>{query}</strong></p>'
                for post in results:
                    content += f"""
                        <div class="post">
                            <h3><a href="/post/{post['id']}">{post['title']}</a></h3>
                            <div class="meta">By {post['author']} on {post['created_at']}</div>
                        </div>
                    """
            else:
                content += f'<p>No results found for: <strong>{query}</strong></p>'
            
            cursor.close()
            conn.close()
        except Exception as e:
            content += f'<div class="error">Search error: {str(e)}</div>'
    
    return render_template_string(HTML_BASE, content=content)


@app.route('/api/posts')
def api_posts():
    """API endpoint - VULNERABLE to UNION-based SQLi."""
    content = '<h2>API Endpoint - UNION-Based SQL Injection</h2>'
    
    content += """
        <div class="vulnerable-section">
            <p><strong>Vulnerability:</strong> Author parameter allows UNION SELECT attacks.</p>
            <p><strong>Test payloads:</strong> Try: <code>?author=Admin' UNION SELECT 1,2,3,4,5--</code></p>
        </div>
        
        <p>API endpoint: <code>/api/posts?author=Author Name</code></p>
    """
    
    author = request.args.get('author', '')
    
    if author:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # VULNERABLE: Direct concatenation - UNION attacks possible!
            sql = f"SELECT id, title, content, author, created_at FROM posts WHERE author = '{author}'"
            cursor.execute(sql)
            results = cursor.fetchall()
            
            content += f'<h3>Results for author: {author}</h3>'
            
            if results:
                content += '<pre style="background: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto;">'
                for post in results:
                    content += f"""
ID: {post['id']}
Title: {post['title']}
Author: {post['author']}
Date: {post['created_at']}
---
"""
                content += '</pre>'
            else:
                content += f'<p>No posts found for author: {author}</p>'
            
            cursor.close()
            conn.close()
        except Exception as e:
            content += f'<div class="error">API Error: {str(e)}</div>'
    else:
        content += '<p>Try: <a href="/api/posts?author=Admin">?author=Admin</a></p>'
    
    return render_template_string(HTML_BASE, content=content)


# =============================================================================
# RUN APPLICATION
# =============================================================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)