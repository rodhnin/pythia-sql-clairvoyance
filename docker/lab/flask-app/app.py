"""
SecureDev Blog — Flask SQL Injection Testing Lab

DELIBERATELY VULNERABLE — Security testing only. Do NOT deploy in production.

Vulnerabilities:
  PYTHIA-SQL-001  Error-based SQLi      GET /post/<id>        (path param id)
  PYTHIA-SQL-001  Error-based SQLi      GET /comment/<id>     (path param id)
  PYTHIA-SQL-010  Boolean blind SQLi    GET /search?q=        (query param q)
  PYTHIA-SQL-010  Boolean blind SQLi    GET /tag?name=        (query param name)
  PYTHIA-SQL-030  UNION-based SQLi      GET /api/posts?author=(query param author)
  PYTHIA-SQL-040  Second-order SQLi     POST /register → GET /profile/<username>
  PYTHIA-SQL-050  ORDER BY injection    GET /posts?sort=&order=(query params)
  PYTHIA-SQL-000  Session-var SQLi      POST /user-input → GET /user-lookup
                  (popup onclick pattern — mirrors DVWA security=high)
"""

from flask import Flask, request, render_template_string, jsonify, session
import pymysql
import os
from pathlib import Path

app = Flask(__name__)
app.secret_key = 'pythia-lab-not-for-production'

# =============================================================================
# DATABASE
# =============================================================================
def get_db():
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', 'mysql'),
        user=os.getenv('MYSQL_USER', 'blog'),
        password=os.getenv('MYSQL_PASSWORD', 'blog123'),
        database=os.getenv('MYSQL_DATABASE', 'blog'),
        cursorclass=pymysql.cursors.DictCursor
    )

# =============================================================================
# BASE TEMPLATE
# =============================================================================
HTML_BASE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureDev Blog — SQL Injection Lab</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; }
        .topbar { background: #0d47a1; color: white; padding: 14px 24px; display: flex; align-items: center; justify-content: space-between; }
        .topbar .logo { font-size: 1.3rem; font-weight: 700; }
        .topbar .logo span { color: #90caf9; }
        .topbar nav a { color: #bbdefb; text-decoration: none; margin-left: 18px; font-size: 0.9rem; transition: color .2s; }
        .topbar nav a:hover { color: white; }
        .container { max-width: 1100px; margin: 0 auto; padding: 24px; display: grid; grid-template-columns: 1fr 300px; gap: 24px; }
        .main { min-width: 0; }
        .sidebar { min-width: 0; }
        @media (max-width: 768px) { .container { grid-template-columns: 1fr; } .sidebar { display: none; } }
        .warning { background: #fff8e1; border-left: 4px solid #ff9800; padding: 10px 14px; margin-bottom: 20px; border-radius: 4px; font-size: 0.85rem; }
        h2 { color: #0d47a1; margin-bottom: 16px; }
        .post-card { background: white; border-radius: 10px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.08); transition: box-shadow .2s; }
        .post-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,.12); }
        .post-card h3 { margin-bottom: 6px; }
        .post-card h3 a { color: #1565c0; text-decoration: none; font-size: 1.1rem; }
        .post-card h3 a:hover { text-decoration: underline; }
        .post-meta { color: #777; font-size: 0.82rem; margin-bottom: 10px; }
        .post-excerpt { color: #555; font-size: 0.92rem; }
        .post-tags { margin-top: 10px; }
        .tag { display: inline-block; background: #e3f2fd; color: #1565c0; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; margin-right: 4px; text-decoration: none; }
        .tag:hover { background: #1565c0; color: white; }
        .view-count { float: right; color: #aaa; font-size: 0.78rem; }
        .post-full { background: white; border-radius: 10px; padding: 28px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
        .post-full h2 { color: #0d47a1; margin-bottom: 8px; }
        .post-full .post-meta { margin-bottom: 16px; }
        .post-content { color: #333; line-height: 1.8; }
        .comment-section { margin-top: 28px; }
        .comment { background: #f5f7fa; padding: 14px; border-radius: 8px; margin-bottom: 10px; border-left: 3px solid #1565c0; }
        .comment-author { font-weight: 600; font-size: 0.9rem; }
        .comment-body { font-size: 0.9rem; margin-top: 4px; color: #555; }
        .error { color: #c62828; background: #ffebee; padding: 12px 16px; border-radius: 8px; border-left: 4px solid #c62828; margin: 12px 0; font-family: monospace; font-size: 0.88rem; white-space: pre-wrap; }
        .search-box { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 20px; }
        .search-box form { display: flex; gap: 8px; align-items: flex-start; flex-wrap: wrap; }
        .search-box input { flex: 1; min-width: 200px; padding: 10px 14px; border: 2px solid #bbdefb; border-radius: 8px; font-size: 0.95rem; outline: none; }
        .search-box input:focus { border-color: #1565c0; }
        .sort-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
        .sort-link { padding: 5px 14px; border-radius: 20px; background: #e3f2fd; color: #1565c0; text-decoration: none; font-size: 0.82rem; transition: all .2s; }
        .sort-link.active, .sort-link:hover { background: #1565c0; color: white; }
        .form-card { background: white; border-radius: 10px; padding: 28px; max-width: 460px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; font-weight: 600; margin-bottom: 6px; font-size: 0.9rem; }
        .form-group input, .form-group textarea { width: 100%; padding: 10px 14px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 0.92rem; outline: none; transition: border .2s; }
        .form-group input:focus, .form-group textarea:focus { border-color: #1565c0; }
        .btn { display: inline-block; background: #1565c0; color: white; padding: 10px 22px; border: none; border-radius: 8px; cursor: pointer; font-size: 0.95rem; text-decoration: none; transition: background .2s; }
        .btn:hover { background: #0d47a1; }
        .btn-block { width: 100%; text-align: center; padding: 12px; }
        .success { background: #e8f5e9; border-left: 4px solid #4caf50; padding: 14px; border-radius: 8px; margin-bottom: 16px; }
        .hint { background: #f3f4fd; border-left: 3px solid #7986cb; padding: 14px; border-radius: 8px; font-size: 0.85rem; margin-top: 16px; }
        .hint code { background: white; padding: 1px 5px; border-radius: 3px; font-family: monospace; color: #c62828; }
        .sidebar-widget { background: white; border-radius: 10px; padding: 18px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
        .sidebar-widget h4 { color: #0d47a1; margin-bottom: 12px; font-size: 0.95rem; border-bottom: 2px solid #e3f2fd; padding-bottom: 8px; }
        .sidebar-widget a { display: block; color: #555; text-decoration: none; padding: 5px 0; font-size: 0.88rem; border-bottom: 1px solid #f0f0f0; }
        .sidebar-widget a:hover { color: #1565c0; }
        .profile-card { background: white; border-radius: 10px; padding: 28px; text-align: center; max-width: 420px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
        .profile-avatar { font-size: 5rem; margin-bottom: 12px; }
        .profile-bio { color: #666; margin: 10px 0; font-size: 0.95rem; }
        .result-count { color: #666; margin-bottom: 12px; font-size: 0.9rem; }
        footer { background: #0d47a1; color: #90caf9; text-align: center; padding: 20px; margin-top: 40px; font-size: 0.85rem; }
        footer a { color: #bbdefb; text-decoration: none; }
    </style>
</head>
<body>
<div class="topbar">
    <div class="logo">Secure<span>Dev</span> Blog</div>
    <nav>
        <a href="/">Home</a>
        <a href="/posts">All Posts</a>
        <a href="/search">Search</a>
        <a href="/register">Register</a>
        <a href="/api/posts">API</a>
    </nav>
</div>
<div class="container">
    <div class="main">
        <div class="warning">⚠️ <strong>DELIBERATELY VULNERABLE</strong> — SQL Injection Testing Lab for Pythia</div>
        {{ content|safe }}
    </div>
    <div class="sidebar">
        <div class="sidebar-widget">
            <h4>Navigation</h4>
            <a href="/">🏠 Home</a>
            <a href="/posts">📝 All Posts</a>
            <a href="/posts?sort=view_count&order=DESC">🔥 Most Popular</a>
            <a href="/posts?sort=created_at&order=DESC">🆕 Newest</a>
            <a href="/search">🔍 Search</a>
            <a href="/register">👤 Register</a>
            <a href="/user-lookup">🔍 User Lookup</a>
        </div>
        <div class="sidebar-widget">
            <h4>Tags</h4>
            <a href="/tag?name=security">🔒 security</a>
            <a href="/tag?name=sql">🗄️ sql</a>
            <a href="/tag?name=webdev">💻 webdev</a>
            <a href="/tag?name=privacy">🔐 privacy</a>
            <a href="/tag?name=devops">⚙️ devops</a>
        </div>
        <div class="sidebar-widget">
            <h4>API Endpoints</h4>
            <a href="/api/posts?author=Admin">/api/posts?author=Admin</a>
            <a href="/api/posts?sort=id&order=DESC">/api/posts?sort=id</a>
            <a href="/api/stats">/api/stats</a>
        </div>
    </div>
</div>
<footer>
    <p><strong>SecureDev Blog — SQL Injection Testing Lab</strong> | Pythia Security Platform</p>
    <p>Vulnerable routes: <a href="/post/1">/post/&lt;id&gt;</a> · <a href="/search?q=test">/search</a> · <a href="/api/posts?author=Admin">/api/posts</a> · <a href="/posts?sort=id&order=ASC">/posts?sort=</a> · <a href="/register">/register</a>→<a href="/profile/test">/profile</a></p>
</footer>
</body>
</html>"""


def render(content):
    return render_template_string(HTML_BASE, content=content)


# =============================================================================
# ROUTES
# =============================================================================

@app.route('/.well-known/<path:filename>')
def wellknown(filename):
    d = Path(__file__).parent / '.well-known'
    fp = d / filename
    if fp.exists():
        return fp.read_text().strip(), 200, {'Content-Type': 'text/plain'}
    return 'Not Found', 404


@app.route('/')
def home():
    content = '<h2>Latest Posts</h2>'
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT id, title, author, view_count, created_at FROM posts ORDER BY created_at DESC LIMIT 5")
        posts = cur.fetchall()
        for p in posts:
            excerpt_sql = "SELECT SUBSTRING(content, 1, 120) AS ex FROM posts WHERE id = %s"
            cur.execute(excerpt_sql, (p['id'],))
            ex = (cur.fetchone() or {}).get('ex', '')
            content += f"""<div class="post-card">
                <div class="view-count">👁 {p['view_count']}</div>
                <h3><a href="/post/{p['id']}">{p['title']}</a></h3>
                <div class="post-meta">By <strong>{p['author']}</strong> · {p['created_at']}</div>
                <div class="post-excerpt">{ex}...</div>
            </div>"""
        cur.close(); conn.close()
    except Exception as e:
        content += f'<div class="error">Error: {e}</div>'
    return render(content)


@app.route('/posts')
def posts():
    sort  = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'DESC').upper()
    if order not in ('ASC', 'DESC'):
        order = 'DESC'

    content = '<h2>All Posts</h2>'
    # Sort controls
    content += '<div class="sort-bar"><span>Sort by: </span>'
    sorts = [('created_at','Date'), ('view_count','Views'), ('title','Title'), ('author','Author'), ('id','ID')]
    for key, label in sorts:
        new_order = 'ASC' if (sort == key and order == 'DESC') else 'DESC'
        arrow = (' ↑' if order == 'ASC' else ' ↓') if sort == key else ''
        active = 'active' if sort == key else ''
        content += f'<a href="/posts?sort={key}&order={new_order}" class="sort-link {active}">{label}{arrow}</a>'
    content += '</div>'

    try:
        conn = get_db(); cur = conn.cursor()
        # VULNERABLE: $sort directly in ORDER BY — PYTHIA-SQL-050
        sql = f"SELECT id, title, author, view_count, created_at FROM posts ORDER BY {sort} {order}"
        cur.execute(sql)
        all_posts = cur.fetchall()
        for p in all_posts:
            content += f"""<div class="post-card">
                <div class="view-count">👁 {p['view_count']}</div>
                <h3><a href="/post/{p['id']}">{p['title']}</a></h3>
                <div class="post-meta">By <strong>{p['author']}</strong> · {p['created_at']}</div>
            </div>"""
        cur.close(); conn.close()
    except Exception as e:
        # VULNERABLE: SQL error exposed (PYTHIA-SQL-050 via ORDER BY injection)
        content += f'<div class="error">SQL Error: {e}</div>'

    return render(content)


@app.route('/post/<post_id>')
def post_detail(post_id):
    content = ''
    try:
        conn = get_db(); cur = conn.cursor()

        # VULNERABLE: Direct f-string concatenation — PYTHIA-SQL-001
        sql = f"SELECT * FROM posts WHERE id = {post_id}"
        cur.execute(sql)
        post = cur.fetchone()

        if post:
            # Update view count (safe)
            cur.execute("UPDATE posts SET view_count = view_count + 1 WHERE id = %s", (post['id'],))
            conn.commit()

            content += f"""<div class="post-full">
                <h2>{post['title']}</h2>
                <div class="post-meta">By <strong>{post['author']}</strong> · {post['created_at']} · 👁 {post['view_count']}</div>
                <div class="post-content"><p>{post['content']}</p></div>
            </div>"""

            # Comments — also VULNERABLE
            cur.execute(f"SELECT * FROM comments WHERE post_id = {post_id} ORDER BY created_at ASC")
            comments = cur.fetchall()
            content += f'<div class="comment-section"><h3>Comments ({len(comments)})</h3>'
            if comments:
                for c in comments:
                    content += f'<div class="comment"><div class="comment-author">{c["author"]}</div><div class="comment-body">{c["content"]}</div></div>'
            else:
                content += '<p>No comments yet.</p>'
            content += '</div>'
        else:
            content += f'<div class="error">Post not found: {post_id}</div>'

        cur.close(); conn.close()
    except Exception as e:
        # VULNERABLE: SQL error message exposed
        content += f'<div class="error">SQL Error: {e}</div>'

    return render(content)


@app.route('/comment/<comment_id>')
def comment_detail(comment_id):
    content = '<h2>Comment Detail</h2>'
    try:
        conn = get_db(); cur = conn.cursor()
        # VULNERABLE: Direct concatenation
        sql = f"SELECT c.*, p.title AS post_title FROM comments c JOIN posts p ON c.post_id = p.id WHERE c.id = {comment_id}"
        cur.execute(sql)
        comment = cur.fetchone()
        if comment:
            content += f'<div class="comment"><div class="comment-author">{comment["author"]} on <a href="/post/{comment["post_id"]}">{comment["post_title"]}</a></div><div class="comment-body">{comment["content"]}</div></div>'
        else:
            content += f'<p>Comment not found: {comment_id}</p>'
        cur.close(); conn.close()
    except Exception as e:
        content += f'<div class="error">SQL Error: {e}</div>'
    return render(content)


@app.route('/search')
def search():
    q = request.args.get('q', '')

    content = '<h2>Search Posts</h2>'
    content += f'''<div class="search-box">
        <form method="GET" action="/search">
            <input type="search" name="q" placeholder="Search posts..." value="{q}" autocomplete="off">
            <button type="submit" class="btn">Search</button>
        </form>
    </div>'''

    if q:
        try:
            conn = get_db(); cur = conn.cursor()
            # VULNERABLE: Direct f-string concatenation — PYTHIA-SQL-010
            sql = f"SELECT id, title, author, view_count, created_at FROM posts WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
            cur.execute(sql)
            results = cur.fetchall()

            if results:
                content += f'<p class="result-count">Found <strong>{len(results)}</strong> results for "<em>{q}</em>"</p>'
                for p in results:
                    content += f'''<div class="post-card">
                        <div class="view-count">👁 {p['view_count']}</div>
                        <h3><a href="/post/{p['id']}">{p['title']}</a></h3>
                        <div class="post-meta">By {p['author']} · {p['created_at']}</div>
                    </div>'''
            else:
                content += f'<p>No results for "<strong>{q}</strong>"</p>'
            cur.close(); conn.close()
        except Exception as e:
            content += f'<div class="error">Search error: {e}</div>'

    return render(content)


@app.route('/tag')
def tag():
    name = request.args.get('name', '')
    content = f'<h2>Posts tagged: {name}</h2>'
    if not name:
        return render('<p>No tag specified.</p>')
    try:
        conn = get_db(); cur = conn.cursor()
        # VULNERABLE: Direct concatenation in LIKE — PYTHIA-SQL-010
        sql = f"SELECT id, title, author, view_count, created_at FROM posts WHERE title LIKE '%{name}%' OR content LIKE '%{name}%'"
        cur.execute(sql)
        results = cur.fetchall()
        for p in results:
            content += f'<div class="post-card"><h3><a href="/post/{p["id"]}">{p["title"]}</a></h3><div class="post-meta">By {p["author"]}</div></div>'
        if not results:
            content += '<p>No posts with this tag.</p>'
        cur.close(); conn.close()
    except Exception as e:
        content += f'<div class="error">SQL Error: {e}</div>'
    return render(content)


@app.route('/register', methods=['GET', 'POST'])
def register():
    content = '<h2>Create Account</h2>'

    if request.method == 'POST':
        username = request.form.get('username', '')
        email    = request.form.get('email', '')
        bio      = request.form.get('bio', '')

        try:
            conn = get_db(); cur = conn.cursor()
            # Store is safe (parameterized) — but the RETRIEVED value will be used unsafely
            cur.execute(
                "INSERT INTO registered_users (username, email, bio) VALUES (%s, %s, %s)",
                (username, email, bio)
            )
            conn.commit()
            cur.close(); conn.close()
            content += f'<div class="success">✓ Account created! <a href="/profile/{username}">View your profile →</a></div>'
        except Exception as e:
            content += f'<div class="error">Registration error: {e}</div>'

    content += '''<div class="form-card">
        <form method="POST" action="/register">
            <div class="form-group"><label>Username *</label><input type="text" name="username" placeholder="Choose a username" required></div>
            <div class="form-group"><label>Email</label><input type="email" name="email" placeholder="your@email.com"></div>
            <div class="form-group"><label>Bio</label><textarea name="bio" placeholder="Tell us about yourself..." rows="3"></textarea></div>
            <button type="submit" class="btn btn-block">Register</button>
        </form>
        <div class="hint">
            <strong>Lab Note:</strong> Try registering with username <code>test'sqli</code> or <code>admin'-- </code>
            then view your <a href="/profile/test">profile</a> to trigger second-order SQL injection.
        </div>
    </div>'''

    return render(content)


@app.route('/profile/<username>')
def profile(username):
    content = '<h2>User Profile</h2>'
    try:
        conn = get_db(); cur = conn.cursor()

        # Step 1: Retrieve stored profile (parameterized — safe)
        cur.execute("SELECT id, username, email, bio, registered_at FROM registered_users WHERE username = %s", (username,))
        prof = cur.fetchone()

        if not prof:
            content += f'<div class="error">Profile not found: {username}</div>'
            cur.close(); conn.close()
            return render(content)

        # Step 2: Second query uses the RAW stored username — SECOND ORDER SQLi!
        stored_name = prof['username']
        # VULNERABLE: stored_name from DB used in a new query without escaping
        sql = f"SELECT id, title, author, created_at FROM posts WHERE author = '{stored_name}'"
        cur.execute(sql)
        authored_posts = cur.fetchall()

        content += f'''<div class="profile-card">
            <div class="profile-avatar">👤</div>
            <h3>{prof['username']}</h3>
            <div class="profile-bio">{prof.get('bio') or 'No bio set.'}</div>
            <div class="post-meta">Registered: {prof['registered_at']}</div>
        </div>'''

        content += f'<h3 style="margin-top:20px">Posts by {prof["username"]} ({len(authored_posts)})</h3>'
        if authored_posts:
            for p in authored_posts:
                content += f'<div class="post-card"><h3><a href="/post/{p["id"]}">{p["title"]}</a></h3><div class="post-meta">{p["created_at"]}</div></div>'
        else:
            content += '<p>No posts found for this author.</p>'

        cur.close(); conn.close()
    except Exception as e:
        # SQL error from second-order payload exposed here
        content += f'<div class="error">SQL Error: {e}</div>'

    return render(content)


# =============================================================================
# SESSION-VARIABLE SQLi (mirrors DVWA security=high popup pattern)
# /user-lookup  — reads session['user_id'] and executes SQL with it (VULNERABLE)
# /user-input   — popup form that sets session['user_id'] (no CSRF, like DVWA high)
# The onclick on /user-lookup opens /user-input in a popup window.
# Pythia must: discover the onclick link, track parent_url, POST payload to
# /user-input, then GET /user-lookup to observe the SQL error.
# =============================================================================

@app.route('/user-lookup')
def user_lookup():
    user_id = session.get('user_id', '')
    content = '''<h2>User Lookup</h2>
    <p>Enter a user ID in the popup to look up their profile.</p>
    <p><a href="/user-lookup" onclick="window.open('/user-input','popup','width=400,height=220');return false;"
       style="display:inline-block;background:#1565c0;color:white;padding:8px 18px;border-radius:8px;text-decoration:none;">
       &#128270; Set User ID (popup)
    </a></p>'''

    if user_id:
        content += f'<p style="margin-top:12px;color:#555;">Looking up user ID: <code>{user_id}</code></p>'
        try:
            conn = get_db(); cur = conn.cursor()
            # VULNERABLE: session value used directly in SQL — PYTHIA-SQL-000
            # Same pattern as DVWA security=high: input stored in session,
            # retrieved and used in a new SQL query without sanitization.
            sql = f"SELECT id, username, email FROM registered_users WHERE id = '{user_id}'"
            cur.execute(sql)
            result = cur.fetchone()
            cur.close(); conn.close()
            if result:
                content += f'<div class="post-card"><strong>{result["username"]}</strong> ({result["email"]})</div>'
            else:
                content += '<p>No user found with that ID.</p>'
        except Exception as e:
            # SQL error exposed — confirms injection
            content += f'<div class="error">SQL Error: {e}</div>'
    else:
        content += '<p style="color:#999;margin-top:8px;">No user ID set — click the button above.</p>'

    return render(content)


@app.route('/user-input', methods=['GET', 'POST'])
def user_input():
    """Popup form — sets session['user_id']. No CSRF token (mirrors DVWA high)."""
    if request.method == 'POST':
        uid = request.form.get('user_id', '')
        session['user_id'] = uid
        return '''<!DOCTYPE html><html><body style="font-family:sans-serif;padding:20px;">
        <p style="color:green;">&#10003; User ID set. Close this window and refresh the lookup page.</p>
        <script>setTimeout(function(){window.close();},1200);</script>
        </body></html>'''

    return '''<!DOCTYPE html>
<html><head><title>Set User ID</title>
<style>body{font-family:sans-serif;padding:20px;background:#f5f7fa;}
input{width:100%;padding:8px;border:2px solid #bbdefb;border-radius:6px;font-size:1rem;}
button{margin-top:10px;width:100%;padding:9px;background:#1565c0;color:white;border:none;border-radius:6px;cursor:pointer;font-size:1rem;}
</style></head>
<body>
<h3 style="color:#0d47a1;margin-bottom:12px;">User ID Lookup</h3>
<form method="POST" action="/user-input">
    <label style="font-size:.9rem;font-weight:600;">Enter User ID:</label>
    <input type="text" name="user_id" placeholder="e.g. 1" autofocus>
    <button type="submit">Submit</button>
</form>
</body></html>'''


# =============================================================================
# API ENDPOINTS (JSON)
# =============================================================================

@app.route('/api/posts')
def api_posts():
    author = request.args.get('author', '')
    sort   = request.args.get('sort', 'id')
    order  = request.args.get('order', 'DESC').upper()
    if order not in ('ASC', 'DESC'):
        order = 'DESC'

    try:
        conn = get_db(); cur = conn.cursor()

        if author:
            # VULNERABLE: Direct f-string — UNION-based SQLi, PYTHIA-SQL-030
            sql = f"SELECT id, title, author, view_count, created_at FROM posts WHERE author = '{author}'"
        else:
            # VULNERABLE: ORDER BY injection — PYTHIA-SQL-050
            sql = f"SELECT id, title, author, view_count, created_at FROM posts ORDER BY {sort} {order}"

        cur.execute(sql)
        results = cur.fetchall()
        cur.close(); conn.close()
        return jsonify({'posts': results, 'count': len(results)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
def api_stats():
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS total FROM posts")
        posts_count = cur.fetchone()['total']
        cur.execute("SELECT COUNT(*) AS total FROM comments")
        comments_count = cur.fetchone()['total']
        cur.execute("SELECT SUM(view_count) AS total FROM posts")
        total_views = cur.fetchone()['total'] or 0
        cur.close(); conn.close()
        return jsonify({'posts': posts_count, 'comments': comments_count, 'total_views': total_views})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/sitemap.xml')
def sitemap():
    urls = [
        '/', '/posts', '/search', '/register',
        '/post/1', '/post/2', '/post/3', '/post/4', '/post/5',
        '/comment/1', '/tag?name=security', '/api/posts',
        '/user-lookup',
    ]
    xml = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    for url in urls:
        xml += f'<url><loc>http://localhost:8082{url}</loc></url>'
    xml += '</urlset>'
    return xml, 200, {'Content-Type': 'application/xml'}


@app.route('/robots.txt')
def robots():
    return ('User-agent: *\nAllow: /\nSitemap: http://localhost:8082/sitemap.xml\n'
            'Disallow: /admin\nDisallow: /api/internal\n'), 200, {'Content-Type': 'text/plain'}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
