"""
Vulnerable Web Application - Testing Target for VigilEdge WAF
This application contains intentional vulnerabilities for testing purposes only.
DO NOT USE IN PRODUCTION - FOR EDUCATIONAL/TESTING PURPOSES ONLY
"""

from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import sqlite3
import os
from typing import Optional
import json

# Create vulnerable app
vulnerable_app = FastAPI(
    title="VulnShop - Vulnerable E-commerce Site",
    description="Intentionally vulnerable application for WAF testing",
    version="1.0.0"
)

# Setup templates and static files
templates = Jinja2Templates(directory="templates")

# Initialize vulnerable database
def init_vulnerable_db():
    """Initialize database with vulnerable schema"""
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Create vulnerable users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    # Create products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    ''')
    
    # Insert sample vulnerable data
    cursor.execute("INSERT OR REPLACE INTO users VALUES (1, 'admin', 'admin123', 'admin@vulnshop.com', 1)")
    cursor.execute("INSERT OR REPLACE INTO users VALUES (2, 'user', 'password', 'user@vulnshop.com', 0)")
    cursor.execute("INSERT OR REPLACE INTO users VALUES (3, 'guest', 'guest', 'guest@vulnshop.com', 0)")
    
    # Insert sample products
    cursor.execute("INSERT OR REPLACE INTO products VALUES (1, 'Laptop', 999.99, 'High-performance laptop')")
    cursor.execute("INSERT OR REPLACE INTO products VALUES (2, 'Phone', 699.99, 'Latest smartphone')")
    cursor.execute("INSERT OR REPLACE INTO products VALUES (3, 'Tablet', 399.99, 'Portable tablet device')")
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_vulnerable_db()

@vulnerable_app.get("/", response_class=HTMLResponse)
async def vulnerable_home(request: Request):
    """Enhanced homepage with role-based navigation"""
    # Get search query from URL parameters (vulnerable to XSS)
    search = request.query_params.get("search", "")
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnShop - Online Store</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; min-height: 100vh; }}
            .header {{ background: linear-gradient(135deg, #007bff, #0056b3); color: white; padding: 40px; text-align: center; }}
            .hero {{ background: #f8f9fa; padding: 50px; text-align: center; }}
            .auth-section {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 30px; padding: 40px; background: #e9ecef; }}
            .auth-card {{ background: white; padding: 30px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); text-align: center; }}
            .auth-card h3 {{ margin-top: 0; }}
            .btn {{ display: inline-block; padding: 12px 25px; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 10px; transition: all 0.3s; }}
            .btn-primary {{ background: #007bff; color: white; }}
            .btn-success {{ background: #28a745; color: white; }}
            .btn-danger {{ background: #dc3545; color: white; }}
            .btn:hover {{ transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }}
            .nav {{ display: flex; justify-content: center; gap: 30px; padding: 20px; background: #343a40; }}
            .nav a {{ color: white; text-decoration: none; font-weight: bold; padding: 10px 20px; border-radius: 5px; }}
            .nav a:hover {{ background: #495057; }}
            .search-box {{ text-align: center; margin: 30px 0; }}
            .search-box input {{ padding: 12px; width: 400px; border: 1px solid #ddd; border-radius: 25px; }}
            .search-box button {{ padding: 12px 25px; background: #007bff; color: white; border: none; border-radius: 25px; cursor: pointer; margin-left: 10px; }}
            .features {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 30px; padding: 50px; }}
            .feature {{ background: #f8f9fa; padding: 30px; border-radius: 10px; text-align: center; }}
            .feature h4 {{ color: #007bff; }}
            .warning {{ background: #fff3cd; color: #856404; padding: 20px; border-radius: 10px; margin: 30px; border: 1px solid #ffeaa7; }}
            .footer {{ background: #343a40; color: white; padding: 30px; text-align: center; }}
            .demo-accounts {{ background: #d1ecf1; padding: 20px; border-radius: 10px; margin: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛒 VulnShop</h1>
                <p>Your One-Stop Vulnerable Shopping Experience</p>
                <p style="font-size: 18px; margin-top: 20px;">🎯 Educational Platform for Security Testing</p>
            </div>
            
            <div class="warning">
                ⚠️ <strong>IMPORTANT:</strong> This is a deliberately vulnerable application created for WAF testing and security education purposes only. Do not use in production environments!
            </div>
            
            <div class="auth-section">
                <div class="auth-card">
                    <h3>👤 Customer Portal</h3>
                    <p>Shop products, manage orders, and track your purchases with our customer account system.</p>
                    <a href="/user/login" class="btn btn-success">Customer Login</a>
                    <a href="/register" class="btn btn-primary">Create Account</a>
                    <div class="demo-accounts">
                        <strong>Demo Account:</strong><br>
                        Username: user<br>
                        Password: password
                    </div>
                </div>
                
                <div class="auth-card">
                    <h3>🔐 Admin Panel</h3>
                    <p>Administrative access for managing users, viewing logs, and configuring system settings.</p>
                    <a href="/admin" class="btn btn-danger">Admin Access</a>
                    <div class="demo-accounts">
                        <strong>Admin Token:</strong><br>
                        admin123
                    </div>
                </div>
                
                <div class="auth-card">
                    <h3>🛍️ Browse Catalog</h3>
                    <p>Explore our product catalog and test various e-commerce functionalities without registration.</p>
                    <a href="/products" class="btn btn-primary">View Products</a>
                    <a href="/contact" class="btn btn-primary">Contact Us</a>
                </div>
            </div>
            
            <div class="nav">
                <a href="/">🏠 Home</a>
                <a href="/products">🛍️ Products</a>
                <a href="/upload">📁 File Upload</a>
                <a href="/contact">📧 Contact</a>
                <a href="/login">🔑 Vulnerable Login</a>
            </div>
            
            <div class="search-box">
                <form method="GET">
                    <input type="text" name="search" placeholder="Search for products (XSS vulnerable)..." value="{search}">
                    <button type="submit">🔍 Search</button>
                </form>
                <div style="margin: 15px 0; color: #666; font-style: italic;">
                    Search Result: {search}
                </div>
            </div>
            
            <div class="features">
                <div class="feature">
                    <h4>🎯 SQL Injection Testing</h4>
                    <p>Test SQL injection vulnerabilities in login forms, product searches, and database queries.</p>
                    <a href="/login" class="btn btn-primary">Test Login</a>
                </div>
                
                <div class="feature">
                    <h4>💉 XSS Vulnerabilities</h4>
                    <p>Practice cross-site scripting attacks through search forms and contact submissions.</p>
                    <a href="/contact" class="btn btn-primary">Test XSS</a>
                </div>
                
                <div class="feature">
                    <h4>📁 File Upload Exploits</h4>
                    <p>Explore file upload vulnerabilities and test malicious file detection systems.</p>
                    <a href="/upload" class="btn btn-primary">Upload Files</a>
                </div>
                
                <div class="feature">
                    <h4>🔐 Authentication Bypass</h4>
                    <p>Test authentication mechanisms and privilege escalation vulnerabilities.</p>
                    <a href="/admin" class="btn btn-primary">Admin Panel</a>
                </div>
                
                <div class="feature">
                    <h4>👥 User Management</h4>
                    <p>Customer registration, profile management, and role-based access control testing.</p>
                    <a href="/register" class="btn btn-primary">Register</a>
                </div>
                
                <div class="feature">
                    <h4>📊 Security Monitoring</h4>
                    <p>View attack logs, system monitoring, and security configuration panels.</p>
                    <a href="/admin?token=admin123" class="btn btn-primary">View Logs</a>
                </div>
            </div>
            
            <div style="background: #f8f9fa; padding: 40px; text-align: center;">
                <h3>🎯 Testing Endpoints</h3>
                <p>Use these endpoints to test your WAF protection:</p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; max-width: 800px; margin: 0 auto; text-align: left;">
                    <div>
                        <strong>SQL Injection:</strong><br>
                        <code>/products?id=1' OR 1=1--</code><br>
                        <code>/login (try: admin' OR '1'='1' --)</code>
                    </div>
                    <div>
                        <strong>XSS Attacks:</strong><br>
                        <code>/?search=&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
                        <code>/contact (in form fields)</code>
                    </div>
                    <div>
                        <strong>File Upload:</strong><br>
                        <code>/upload (try malicious files)</code><br>
                        <code>/file?path=../../../etc/passwd</code>
                    </div>
                    <div>
                        <strong>Authentication:</strong><br>
                        <code>/admin?token=admin123</code><br>
                        <code>/admin/users (direct access)</code>
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p>&copy; 2024 VulnShop - Educational Security Testing Platform</p>
                <p>Created for WAF testing and cybersecurity education</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnShop - Online Store</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #007bff; padding-bottom: 20px; }}
            .nav {{ display: flex; justify-content: center; gap: 20px; margin: 20px 0; }}
            .nav a {{ text-decoration: none; color: #007bff; font-weight: bold; padding: 10px 15px; border-radius: 5px; }}
            .nav a:hover {{ background: #007bff; color: white; }}
            .search-box {{ text-align: center; margin: 20px 0; }}
            .search-box input {{ padding: 10px; width: 300px; border: 1px solid #ddd; border-radius: 5px; }}
            .search-box button {{ padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }}
            .products {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }}
            .product {{ border: 1px solid #ddd; padding: 20px; border-radius: 10px; text-align: center; }}
            .product img {{ width: 100px; height: 100px; object-fit: cover; }}
            .warning {{ background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛒 VulnShop</h1>
                <p>Your One-Stop Vulnerable Shopping Experience</p>
                <div class="warning">
                    ⚠️ <strong>WARNING:</strong> This is a deliberately vulnerable application for WAF testing purposes only!
                </div>
            </div>
            
            <div class="nav">
                <a href="/">Home</a>
                <a href="/login">Login</a>
                <a href="/products">Products</a>
                <a href="/admin">Admin Panel</a>
                <a href="/contact">Contact</a>
                <a href="/upload">File Upload</a>
            </div>
            
            <div class="search-box">
                <form method="GET">
                    <input type="text" name="search" placeholder="Search products..." value="{search}">
                    <button type="submit">Search</button>
                </form>
                <div style="margin: 10px 0; color: #666;">
                    Search Result: {search}
                </div>
            </div>
            
            <div class="products">
                <div class="product">
                    <h3>💻 Premium Laptop</h3>
                    <p>Price: $999.99</p>
                    <p>High-performance laptop for professionals</p>
                    <button onclick="alert('Added to cart!')">Add to Cart</button>
                </div>
                <div class="product">
                    <h3>📱 Smartphone</h3>
                    <p>Price: $699.99</p>
                    <p>Latest model with advanced features</p>
                    <button onclick="alert('Added to cart!')">Add to Cart</button>
                </div>
                <div class="product">
                    <h3>📋 Tablet</h3>
                    <p>Price: $399.99</p>
                    <p>Portable device for work and entertainment</p>
                    <button onclick="alert('Added to cart!')">Add to Cart</button>
                </div>
            </div>
            
            <div style="margin-top: 50px; text-align: center; border-top: 1px solid #ddd; padding-top: 20px;">
                <h3>🎯 Attack Testing Endpoints</h3>
                <p>Try these endpoints to test your WAF:</p>
                <ul style="text-align: left; max-width: 600px; margin: 0 auto;">
                    <li><strong>SQL Injection:</strong> <code>/products?id=1' OR 1=1--</code></li>
                    <li><strong>XSS:</strong> <code>/?search=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                    <li><strong>Login Bypass:</strong> <code>/login</code> (try SQL injection)</li>
                    <li><strong>File Upload:</strong> <code>/upload</code> (upload malicious files)</li>
                    <li><strong>Directory Traversal:</strong> <code>/file?path=../../../etc/passwd</code></li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

@vulnerable_app.get("/login", response_class=HTMLResponse)
async def login_form():
    """Vulnerable login form"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
            .warning { background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .attack-examples { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Login to VulnShop</h2>
            <div class="warning">
                ⚠️ This login form is vulnerable to SQL injection attacks!
            </div>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
            </form>
            
            <div class="attack-examples">
                <h4>🎯 SQL Injection Attack Examples:</h4>
                <ul>
                    <li><code>admin' OR '1'='1' --</code></li>
                    <li><code>' UNION SELECT * FROM users --</code></li>
                    <li><code>admin'; DROP TABLE users; --</code></li>
                </ul>
            </div>
            
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.post("/login")
async def vulnerable_login(username: str = Form(...), password: str = Form(...)):
    """Vulnerable login endpoint with SQL injection"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # VULNERABLE: Direct string concatenation (SQL Injection)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"Executing query: {query}")  # For demonstration
        
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return JSONResponse({
                "status": "success",
                "message": f"Login successful! Welcome {user[1]}",
                "user_id": user[0],
                "is_admin": bool(user[4]),
                "executed_query": query  # Show the vulnerable query
            })
        else:
            return JSONResponse({
                "status": "error",
                "message": "Invalid credentials",
                "executed_query": query
            }, status_code=401)
            
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": f"Database error: {str(e)}",
            "executed_query": query
        }, status_code=500)

@vulnerable_app.get("/products")
async def vulnerable_products(id: Optional[int] = None, search: Optional[str] = None):
    """Vulnerable products endpoint with SQL injection"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        if id:
            # VULNERABLE: Direct parameter injection
            query = f"SELECT * FROM products WHERE id = {id}"
        elif search:
            # VULNERABLE: String injection
            query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
        else:
            query = "SELECT * FROM products"
        
        print(f"Executing query: {query}")
        cursor.execute(query)
        products = cursor.fetchall()
        conn.close()
        
        return JSONResponse({
            "products": products,
            "executed_query": query,
            "vulnerability": "SQL injection possible via 'id' and 'search' parameters"
        })
        
    except Exception as e:
        return JSONResponse({
            "error": str(e),
            "executed_query": query,
            "message": "SQL injection may have caused this error"
        }, status_code=500)

@vulnerable_app.get("/upload", response_class=HTMLResponse)
async def upload_form():
    """Vulnerable file upload form"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>File Upload - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .warning { background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .upload-area { border: 2px dashed #007bff; padding: 40px; text-align: center; border-radius: 10px; margin: 20px 0; }
            .form-group { margin: 15px 0; }
            button { padding: 12px 24px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📁 File Upload</h2>
            <div class="warning">
                ⚠️ This upload endpoint accepts any file type without validation!
            </div>
            
            <form method="POST" action="/upload" enctype="multipart/form-data">
                <div class="upload-area">
                    <input type="file" name="file" required>
                    <p>Select any file to upload (no restrictions!)</p>
                </div>
                <button type="submit">Upload File</button>
            </form>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <h4>🎯 Attack Examples:</h4>
                <ul>
                    <li>Upload PHP shell: <code>shell.php</code></li>
                    <li>Upload malicious script: <code>malware.js</code></li>
                    <li>Upload executable: <code>virus.exe</code></li>
                    <li>Upload with double extension: <code>image.jpg.php</code></li>
                </ul>
            </div>
            
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    """

@vulnerable_app.post("/upload")
async def vulnerable_upload(file: UploadFile = File(...)):
    """Vulnerable file upload endpoint"""
    try:
        # VULNERABLE: No file type validation, no size limits
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, file.filename)
        
        # Save file without any validation
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        return JSONResponse({
            "status": "success",
            "message": f"File '{file.filename}' uploaded successfully!",
            "file_path": file_path,
            "file_size": len(content),
            "vulnerability": "No file type validation or size limits applied"
        })
        
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": str(e)
        }, status_code=500)

@vulnerable_app.get("/file")
async def vulnerable_file_read(path: str):
    """Vulnerable file reading endpoint (Directory Traversal)"""
    try:
        # VULNERABLE: Direct file path access
        full_path = os.path.join("uploads", path)
        
        # Try to read the file
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        return JSONResponse({
            "file_path": full_path,
            "content": content[:1000],  # Limit output
            "vulnerability": "Directory traversal possible - try '../../../etc/passwd'"
        })
        
    except Exception as e:
        return JSONResponse({
            "error": str(e),
            "attempted_path": path,
            "vulnerability": "Directory traversal attack detected"
        }, status_code=500)

@vulnerable_app.get("/admin")
async def vulnerable_admin(token: Optional[str] = None):
    """Vulnerable admin panel"""
    # VULNERABLE: Weak authentication
    if token != "admin123":
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>Admin Access Required</title></head>
        <body style="font-family: Arial; margin: 40px;">
            <h2>🔒 Admin Access Required</h2>
            <p>Please provide admin token:</p>
            <form method="GET">
                <input type="text" name="token" placeholder="Enter admin token">
                <button type="submit">Access</button>
            </form>
            <p><strong>Hint:</strong> Try common passwords like 'admin123', 'password', '123456'</p>
            <p><a href="/">← Back to Home</a></p>
        </body>
        </html>
        """)
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel - VulnShop</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }}
            .header {{ background: #dc3545; color: white; padding: 20px; text-align: center; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 30px; }}
            .dashboard-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }}
            .card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .card h3 {{ color: #dc3545; margin-top: 0; }}
            .btn {{ display: inline-block; padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }}
            .btn:hover {{ background: #c82333; }}
            .stats {{ display: flex; justify-content: space-around; background: #d4edda; padding: 20px; border-radius: 10px; margin: 20px 0; }}
            .stat {{ text-align: center; }}
            .stat-number {{ font-size: 2em; font-weight: bold; color: #155724; }}
            .nav {{ background: #343a40; padding: 15px; }}
            .nav a {{ color: white; text-decoration: none; margin: 0 15px; }}
            .nav a:hover {{ color: #ffc107; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔐 VulnShop Admin Dashboard</h1>
            <p>Administrative Control Panel - Access Token: admin123</p>
        </div>
        
        <div class="nav">
            <a href="/admin?token=admin123">Dashboard</a>
            <a href="/admin/users?token=admin123">User Management</a>
            <a href="/admin/logs?token=admin123">System Logs</a>
            <a href="/admin/config?token=admin123">Configuration</a>
            <a href="/">← Back to VulnShop</a>
        </div>
        
        <div class="container">
            <div class="stats">
                <div class="stat">
                    <div class="stat-number">3</div>
                    <div>Total Users</div>
                </div>
                <div class="stat">
                    <div class="stat-number">3</div>
                    <div>Products</div>
                </div>
                <div class="stat">
                    <div class="stat-number">15</div>
                    <div>Attack Attempts</div>
                </div>
                <div class="stat">
                    <div class="stat-number">Active</div>
                    <div>System Status</div>
                </div>
            </div>
            
            <div class="dashboard-grid">
                <div class="card">
                    <h3>👥 User Management</h3>
                    <p>Manage registered users, view profiles, and control access permissions.</p>
                    <a href="/admin/users?token=admin123" class="btn">Manage Users</a>
                </div>
                
                <div class="card">
                    <h3>📊 System Logs</h3>
                    <p>View application logs, security events, and attack attempts.</p>
                    <a href="/admin/logs?token=admin123" class="btn">View Logs</a>
                </div>
                
                <div class="card">
                    <h3>⚙️ Configuration</h3>
                    <p>System settings, security configurations, and application parameters.</p>
                    <a href="/admin/config?token=admin123" class="btn">Configure</a>
                </div>
                
                <div class="card">
                    <h3>🛍️ Product Management</h3>
                    <p>Add, edit, or remove products from the store catalog.</p>
                    <a href="/admin/products?token=admin123" class="btn">Manage Products</a>
                </div>
                
                <div class="card">
                    <h3>🔍 Vulnerability Testing</h3>
                    <p>Access testing endpoints and vulnerability demonstrations.</p>
                    <a href="/admin/testing?token=admin123" class="btn">Testing Tools</a>
                </div>
                
                <div class="card">
                    <h3>💾 Database</h3>
                    <p>Direct database access and SQL query interface (Vulnerable!).</p>
                    <a href="/admin/database?token=admin123" class="btn">Database Access</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.get("/admin/users")
async def admin_users(token: Optional[str] = None):
    """Admin user management page"""
    if token != "admin123":
        return HTMLResponse("<h2>Access Denied</h2><p><a href='/admin'>Go to Admin Login</a></p>")
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    users_html = ""
    for user in users:
        admin_badge = "👑 Admin" if user[4] else "👤 User"
        users_html += f"""
        <tr>
            <td>{user[0]}</td>
            <td>{user[1]}</td>
            <td>***hidden***</td>
            <td>{user[2]}</td>
            <td>{admin_badge}</td>
            <td><button onclick="deleteUser({user[0]})">Delete</button></td>
        </tr>
        """
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Management - Admin</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background: #dc3545; color: white; }}
            .btn {{ padding: 8px 15px; background: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer; }}
            .nav {{ margin-bottom: 20px; }}
            .nav a {{ color: #dc3545; text-decoration: none; margin-right: 15px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="nav">
                <a href="/admin?token=admin123">← Back to Dashboard</a>
            </div>
            <h2>👥 User Management</h2>
            <table>
                <thead>
                    <tr><th>ID</th><th>Username</th><th>Password</th><th>Email</th><th>Role</th><th>Actions</th></tr>
                </thead>
                <tbody>
                    {users_html}
                </tbody>
            </table>
        </div>
        <script>
            function deleteUser(id) {{
                if(confirm('Delete user with ID ' + id + '?')) {{
                    alert('Delete functionality not implemented (for safety)');
                }}
            }}
        </script>
    </body>
    </html>
    """)

@vulnerable_app.get("/admin/logs")
async def admin_logs(token: Optional[str] = None):
    """Admin system logs page"""
    if token != "admin123":
        return HTMLResponse("<h2>Access Denied</h2><p><a href='/admin'>Go to Admin Login</a></p>")
    
    import datetime
    logs = [
        ("2024-01-15 10:30:25", "INFO", "User login attempt: admin"),
        ("2024-01-15 10:31:15", "WARNING", "SQL Injection detected from IP 192.168.1.100"),
        ("2024-01-15 10:32:00", "ERROR", "Failed login attempt: admin' OR '1'='1'"),
        ("2024-01-15 10:33:45", "INFO", "File upload: malicious.php blocked"),
        ("2024-01-15 10:35:20", "CRITICAL", "XSS attempt detected in search parameter"),
        ("2024-01-15 10:36:10", "INFO", "Admin panel accessed with token"),
        ("2024-01-15 10:37:55", "WARNING", "Unusual traffic pattern detected"),
        ("2024-01-15 10:38:30", "INFO", "Database query executed: SELECT * FROM products"),
    ]
    
    logs_html = ""
    for log in logs:
        color = {"INFO": "#28a745", "WARNING": "#ffc107", "ERROR": "#fd7e14", "CRITICAL": "#dc3545"}
        logs_html += f"""
        <tr>
            <td>{log[0]}</td>
            <td><span style="color: {color.get(log[1], '#000')}; font-weight: bold;">{log[1]}</span></td>
            <td>{log[2]}</td>
        </tr>
        """
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>System Logs - Admin</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background: #dc3545; color: white; }}
            .nav {{ margin-bottom: 20px; }}
            .nav a {{ color: #dc3545; text-decoration: none; margin-right: 15px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="nav">
                <a href="/admin?token=admin123">← Back to Dashboard</a>
            </div>
            <h2>📊 System Logs</h2>
            <table>
                <thead>
                    <tr><th>Timestamp</th><th>Level</th><th>Message</th></tr>
                </thead>
                <tbody>
                    {logs_html}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.get("/admin/config")
async def admin_config(token: Optional[str] = None):
    """Admin configuration page"""
    if token != "admin123":
        return HTMLResponse("<h2>Access Denied</h2><p><a href='/admin'>Go to Admin Login</a></p>")
    
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Configuration - Admin</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .config-section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
            input, select { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 3px; }
            .btn { padding: 10px 20px; background: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer; }
            .nav { margin-bottom: 20px; }
            .nav a { color: #dc3545; text-decoration: none; margin-right: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="nav">
                <a href="/admin?token=admin123">← Back to Dashboard</a>
            </div>
            <h2>⚙️ System Configuration</h2>
            
            <div class="config-section">
                <h3>Security Settings</h3>
                <label>Admin Token: <input type="text" value="admin123" readonly></label><br>
                <label>Max Login Attempts: <input type="number" value="3"></label><br>
                <label>Session Timeout: <select><option>30 min</option><option>1 hour</option><option>2 hours</option></select></label>
            </div>
            
            <div class="config-section">
                <h3>Application Settings</h3>
                <label>Site Name: <input type="text" value="VulnShop"></label><br>
                <label>Debug Mode: <input type="checkbox" checked> Enabled</label><br>
                <label>Logging Level: <select><option>DEBUG</option><option>INFO</option><option>WARNING</option><option>ERROR</option></select></label>
            </div>
            
            <div class="config-section">
                <h3>Database Settings</h3>
                <label>Database File: <input type="text" value="vulnerable.db" readonly></label><br>
                <label>Backup Interval: <select><option>Daily</option><option>Weekly</option><option>Monthly</option></select></label>
            </div>
            
            <button class="btn" onclick="alert('Configuration saved!')">Save Configuration</button>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.get("/register", response_class=HTMLResponse)
async def register_form():
    """Customer registration form"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; font-weight: bold; color: #333; }
            input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
            .btn { width: 100%; padding: 15px; background: #007bff; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; margin-top: 20px; }
            .btn:hover { background: #0056b3; }
            .links { text-align: center; margin-top: 20px; }
            .links a { color: #007bff; text-decoration: none; margin: 0 10px; }
            .header { text-align: center; margin-bottom: 30px; }
            .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>🛍️ Join VulnShop</h2>
                <p>Create your customer account</p>
            </div>
            
            <form method="POST" action="/register">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                
                <button type="submit" class="btn">Create Account</button>
            </form>
            
            <div class="links">
                <a href="/login">Already have an account? Login</a> | 
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.post("/register")
async def register_user(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Register new customer account"""
    try:
        # Basic validation
        if password != confirm_password:
            return HTMLResponse("""
            <div style="font-family: Arial; margin: 40px; text-align: center;">
                <h2>❌ Registration Failed</h2>
                <p>Passwords do not match!</p>
                <a href="/register">← Try Again</a>
            </div>
            """, status_code=400)
        
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return HTMLResponse("""
            <div style="font-family: Arial; margin: 40px; text-align: center;">
                <h2>❌ Registration Failed</h2>
                <p>Username already exists!</p>
                <a href="/register">← Try Again</a>
            </div>
            """, status_code=400)
        
        # Insert new user (non-admin by default)
        cursor.execute(
            "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, 0)",
            (username, password, email)
        )
        conn.commit()
        conn.close()
        
        return HTMLResponse(f"""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>✅ Registration Successful!</h2>
            <p>Welcome to VulnShop, {username}!</p>
            <p>Your account has been created successfully.</p>
            <div style="margin: 30px 0;">
                <a href="/user/login" style="background: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px;">Login to Your Account</a>
            </div>
            <p><a href="/">← Back to Home</a></p>
        </div>
        """)
        
    except Exception as e:
        return HTMLResponse(f"""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>❌ Registration Error</h2>
            <p>An error occurred: {str(e)}</p>
            <a href="/register">← Try Again</a>
        </div>
        """, status_code=500)

@vulnerable_app.get("/user/login", response_class=HTMLResponse)
async def user_login_form():
    """Customer/User login form (separate from admin)"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Customer Login - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; font-weight: bold; color: #333; }
            input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
            .btn { width: 100%; padding: 15px; background: #28a745; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; }
            .btn:hover { background: #218838; }
            .links { text-align: center; margin-top: 20px; }
            .links a { color: #007bff; text-decoration: none; margin: 0 10px; }
            .header { text-align: center; margin-bottom: 30px; color: #28a745; }
            .demo-accounts { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>🛍️ Customer Login</h2>
                <p>Access your VulnShop account</p>
            </div>
            
            <form method="POST" action="/user/login">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit" class="btn">Login to Account</button>
            </form>
            
            <div class="demo-accounts">
                <h4>Demo Accounts:</h4>
                <p><strong>Customer:</strong> user / password</p>
                <p><strong>Guest:</strong> guest / guest</p>
            </div>
            
            <div class="links">
                <a href="/register">Don't have an account? Register</a> | 
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.post("/user/login")
async def user_login_auth(username: str = Form(...), password: str = Form(...)):
    """Customer/User authentication"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Secure query (not vulnerable like admin login)
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user and user[4] == 0:  # Check if non-admin user
            # Redirect to customer dashboard
            return HTMLResponse(f"""
            <script>
                sessionStorage.setItem('vulnshop_user', '{user[1]}');
                sessionStorage.setItem('vulnshop_user_id', '{user[0]}');
                window.location.href = '/user/dashboard';
            </script>
            """)
        else:
            return HTMLResponse("""
            <div style="font-family: Arial; margin: 40px; text-align: center;">
                <h2>❌ Login Failed</h2>
                <p>Invalid credentials or admin account detected!</p>
                <p>Use <a href="/admin">Admin Panel</a> for administrative access.</p>
                <a href="/user/login">← Try Again</a>
            </div>
            """, status_code=401)
            
    except Exception as e:
        return HTMLResponse(f"""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>❌ Login Error</h2>
            <p>An error occurred: {str(e)}</p>
            <a href="/user/login">← Try Again</a>
        </div>
        """, status_code=500)

@vulnerable_app.get("/user/dashboard", response_class=HTMLResponse)
async def user_dashboard():
    """Customer dashboard with limited features"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>My Account - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }
            .header { background: #28a745; color: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; }
            .container { max-width: 1000px; margin: 0 auto; padding: 30px; }
            .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }
            .card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .card h3 { color: #28a745; margin-top: 0; }
            .btn { display: inline-block; padding: 10px 20px; background: #28a745; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }
            .btn:hover { background: #218838; }
            .stats { display: flex; justify-content: space-around; background: #d1ecf1; padding: 20px; border-radius: 10px; margin: 20px 0; }
            .stat { text-align: center; }
            .stat-number { font-size: 1.5em; font-weight: bold; color: #0c5460; }
            .user-info { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .logout { background: #dc3545; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>🛍️ VulnShop - My Account</h1>
                <p>Customer Dashboard</p>
            </div>
            <button class="logout" onclick="logout()">Logout</button>
        </div>
        
        <div class="container">
            <div class="user-info">
                <h3>👤 Welcome, <span id="username">Customer</span>!</h3>
                <p>Account ID: <span id="user-id">-</span> | Account Type: Customer</p>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <div class="stat-number">5</div>
                    <div>Orders</div>
                </div>
                <div class="stat">
                    <div class="stat-number">$299.99</div>
                    <div>Total Spent</div>
                </div>
                <div class="stat">
                    <div class="stat-number">2</div>
                    <div>Cart Items</div>
                </div>
                <div class="stat">
                    <div class="stat-number">Gold</div>
                    <div>Member Status</div>
                </div>
            </div>
            
            <div class="dashboard-grid">
                <div class="card">
                    <h3>🛒 My Orders</h3>
                    <p>View your order history and track current shipments.</p>
                    <a href="/user/orders" class="btn">View Orders</a>
                </div>
                
                <div class="card">
                    <h3>👤 Profile Settings</h3>
                    <p>Update your personal information and account preferences.</p>
                    <a href="/user/profile" class="btn">Edit Profile</a>
                </div>
                
                <div class="card">
                    <h3>🛍️ Browse Products</h3>
                    <p>Explore our catalog and add items to your cart.</p>
                    <a href="/products" class="btn">Shop Now</a>
                </div>
                
                <div class="card">
                    <h3>💰 Payment Methods</h3>
                    <p>Manage your saved payment options and billing addresses.</p>
                    <a href="/user/payments" class="btn">Manage Payments</a>
                </div>
                
                <div class="card">
                    <h3>📧 Contact Support</h3>
                    <p>Get help with your orders or account issues.</p>
                    <a href="/contact" class="btn">Contact Us</a>
                </div>
                
                <div class="card">
                    <h3>🔐 Security</h3>
                    <p>Change your password and review account security.</p>
                    <a href="/user/security" class="btn">Security Settings</a>
                </div>
            </div>
        </div>
        
        <script>
            // Load user info from session storage
            const username = sessionStorage.getItem('vulnshop_user');
            const userId = sessionStorage.getItem('vulnshop_user_id');
            
            if (username) {
                document.getElementById('username').textContent = username;
                document.getElementById('user-id').textContent = userId || 'Unknown';
            } else {
                // Redirect to login if no session
                window.location.href = '/user/login';
            }
            
            function logout() {
                sessionStorage.removeItem('vulnshop_user');
                sessionStorage.removeItem('vulnshop_user_id');
                alert('Logged out successfully!');
                window.location.href = '/';
            }
        </script>
    </body>
    </html>
    """)

@vulnerable_app.get("/user/profile", response_class=HTMLResponse)
async def user_profile():
    """User profile management page"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>My Profile - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }
            .header { background: #28a745; color: white; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; padding: 30px; }
            .profile-card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin: 20px 0; }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; font-weight: bold; color: #333; }
            input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; }
            .btn { padding: 12px 25px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 10px 5px; }
            .btn-secondary { background: #6c757d; }
            .nav { margin-bottom: 20px; }
            .nav a { color: #28a745; text-decoration: none; margin-right: 15px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>👤 My Profile</h1>
            <p>Manage your account information</p>
        </div>
        
        <div class="container">
            <div class="nav">
                <a href="/user/dashboard">← Back to Dashboard</a>
            </div>
            
            <div class="profile-card">
                <h3>Personal Information</h3>
                <form method="POST" action="/user/profile/update">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" readonly>
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Email Address:</label>
                        <input type="email" id="email" name="email">
                    </div>
                    
                    <div class="form-group">
                        <label for="full_name">Full Name:</label>
                        <input type="text" id="full_name" name="full_name" placeholder="Enter your full name">
                    </div>
                    
                    <div class="form-group">
                        <label for="phone">Phone Number:</label>
                        <input type="tel" id="phone" name="phone" placeholder="Enter your phone number">
                    </div>
                    
                    <div class="form-group">
                        <label for="address">Address:</label>
                        <input type="text" id="address" name="address" placeholder="Enter your address">
                    </div>
                    
                    <button type="submit" class="btn">Update Profile</button>
                    <button type="button" class="btn btn-secondary" onclick="loadUserData()">Reset</button>
                </form>
            </div>
            
            <div class="profile-card">
                <h3>Account Security</h3>
                <p>Last Login: <span id="last-login">Today</span></p>
                <p>Account Created: <span id="account-created">Recently</span></p>
                <a href="/user/security" class="btn">Change Password</a>
            </div>
        </div>
        
        <script>
            function loadUserData() {
                const username = sessionStorage.getItem('vulnshop_user');
                if (username) {
                    document.getElementById('username').value = username;
                    // Load additional user data would go here
                } else {
                    window.location.href = '/user/login';
                }
            }
            
            // Load user data on page load
            loadUserData();
        </script>
    </body>
    </html>
    """)

@vulnerable_app.post("/user/profile/update")
async def update_user_profile(
    username: str = Form(...),
    email: str = Form(...),
    full_name: str = Form(None),
    phone: str = Form(None),
    address: str = Form(None)
):
    """Update user profile information"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Update email in users table
        cursor.execute("UPDATE users SET email = ? WHERE username = ?", (email, username))
        
        # Note: In a real app, you'd have a separate profile table for additional info
        # For simplicity, we'll just update the email
        
        conn.commit()
        conn.close()
        
        return HTMLResponse("""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>✅ Profile Updated!</h2>
            <p>Your profile information has been updated successfully.</p>
            <a href="/user/profile" style="background: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px;">Back to Profile</a>
        </div>
        """)
        
    except Exception as e:
        return HTMLResponse(f"""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>❌ Update Failed</h2>
            <p>Error: {str(e)}</p>
            <a href="/user/profile">← Back to Profile</a>
        </div>
        """, status_code=500)

@vulnerable_app.get("/user/orders", response_class=HTMLResponse)
async def user_orders():
    """User orders page"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>My Orders - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }
            .header { background: #28a745; color: white; padding: 20px; }
            .container { max-width: 1000px; margin: 0 auto; padding: 30px; }
            .order-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin: 15px 0; }
            .order-status { padding: 5px 15px; border-radius: 15px; color: white; font-size: 12px; }
            .status-delivered { background: #28a745; }
            .status-shipped { background: #007bff; }
            .status-processing { background: #ffc107; color: #000; }
            .nav { margin-bottom: 20px; }
            .nav a { color: #28a745; text-decoration: none; margin-right: 15px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>📦 My Orders</h1>
            <p>Track your purchase history</p>
        </div>
        
        <div class="container">
            <div class="nav">
                <a href="/user/dashboard">← Back to Dashboard</a>
            </div>
            
            <div class="order-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h4>Order #1001</h4>
                        <p>Placed on: January 15, 2024</p>
                    </div>
                    <span class="order-status status-delivered">Delivered</span>
                </div>
                <p><strong>Items:</strong> Premium Laptop, Wireless Mouse</p>
                <p><strong>Total:</strong> $1,099.98</p>
            </div>
            
            <div class="order-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h4>Order #1002</h4>
                        <p>Placed on: January 20, 2024</p>
                    </div>
                    <span class="order-status status-shipped">Shipped</span>
                </div>
                <p><strong>Items:</strong> Smartphone Case, Screen Protector</p>
                <p><strong>Total:</strong> $39.99</p>
            </div>
            
            <div class="order-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h4>Order #1003</h4>
                        <p>Placed on: January 22, 2024</p>
                    </div>
                    <span class="order-status status-processing">Processing</span>
                </div>
                <p><strong>Items:</strong> Tablet, Stylus Pen</p>
                <p><strong>Total:</strong> $449.99</p>
            </div>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.get("/contact")
async def contact_form():
    """Contact form with XSS vulnerability"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .warning { background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📧 Contact Us</h2>
            <div class="warning">
                ⚠️ This form is vulnerable to XSS attacks!
            </div>
            
            <form method="POST" action="/contact">
                <div style="margin: 15px 0;">
                    <label>Name:</label><br>
                    <input type="text" name="name" style="width: 100%; padding: 10px;">
                </div>
                <div style="margin: 15px 0;">
                    <label>Message:</label><br>
                    <textarea name="message" style="width: 100%; padding: 10px; height: 100px;"></textarea>
                </div>
                <button type="submit" style="padding: 12px 24px; background: #007bff; color: white; border: none; border-radius: 5px;">Send Message</button>
            </form>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <h4>🎯 XSS Attack Examples:</h4>
                <ul>
                    <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                    <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                    <li><code>&lt;svg onload=alert('XSS')&gt;&lt;/svg&gt;</code></li>
                </ul>
            </div>
            
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.post("/contact")
async def vulnerable_contact(name: str = Form(...), message: str = Form(...)):
    """Vulnerable contact form that reflects input without sanitization"""
    # VULNERABLE: Direct reflection without sanitization
    response_html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Message Received</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h2>✅ Message Received!</h2>
        <div style="background: #d4edda; padding: 20px; border-radius: 5px;">
            <p><strong>From:</strong> {name}</p>
            <p><strong>Message:</strong> {message}</p>
        </div>
        <p><a href="/contact">← Send Another Message</a></p>
        <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
    """
    return HTMLResponse(response_html)

# Health check endpoint
@vulnerable_app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "app": "VulnShop", "purpose": "WAF Testing Target"}

def find_available_port(start_port=8080, max_attempts=10):
    """Find an available port starting from start_port"""
    import socket
    
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return None

if __name__ == "__main__":
    print("🎯 Starting Vulnerable Web Application for WAF Testing")
    print("⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("🔥 DO NOT USE IN PRODUCTION")
    
    # Find available port
    available_port = find_available_port(8080)
    if available_port is None:
        print("❌ ERROR: Could not find an available port between 8080-8089")
        print("� Solution: Close other applications using these ports")
        exit(1)
    
    print(f"�📡 Server will start on http://localhost:{available_port}")
    
    if available_port != 8080:
        print(f"ℹ️  Note: Using port {available_port} instead of 8080 (port was in use)")
        print(f"📝 Update your WAF proxy to use: http://localhost:{available_port}")
    
    import uvicorn
    uvicorn.run(vulnerable_app, host="127.0.0.1", port=available_port)
