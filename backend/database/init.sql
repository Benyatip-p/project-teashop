DROP TABLE IF EXISTS
    order_items,
    orders,
    products,
    categories,
    audit_logs,
    refresh_tokens,
    role_permissions,
    permissions,
    user_roles,
    roles,
    users
CASCADE;

-- ===================================
-- 1. ตารางกลุ่ม Authentication & Users
-- ===================================

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index สำหรับ login
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active);

-- ตาราง Roles
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_roles_name ON roles(name);

-- ตาราง User-Role Assignment
CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);

-- ตาราง Permissions
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_permissions_name ON permissions(name);

-- ตาราง Role-Permission Assignment
CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- ตาราง Refresh Tokens
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(500) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    replaced_by VARCHAR(500)
);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);

-- ตาราง Audit Logs 
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(50),
    resource_id VARCHAR(50),
    details JSONB,
    ip_address VARCHAR(50),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);

-- หมวดหมู่สินค้า
CREATE TABLE categories (
    id SERIAL PRIMARY KEY,
    parent_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    image_url TEXT,
    is_featured BOOLEAN DEFAULT false, -- false = ไม่โชว์, true = โชว์ในหน้าแรก
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_categories_parent ON categories(parent_id);

-- สินค้า
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price NUMERIC(10, 2) NOT NULL,
    stock INTEGER DEFAULT 0,
    image_url TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_products_category ON products(category_id);
CREATE INDEX idx_products_name ON products(name);

-- คำสั่งซื้อ
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    total_amount NUMERIC(10, 2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending', -- pending, processing, shipped, completed, cancelled
    customer_name VARCHAR(100),
    shipping_address TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_orders_user ON orders(user_id);
CREATE INDEX idx_orders_status ON orders(status);

-- รายการสินค้าในคำสั่งซื้อ
CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id),
    quantity INTEGER NOT NULL,
    price_per_unit NUMERIC(10, 2) NOT NULL -- ราคา ณ ตอนที่ซื้อ
);
CREATE INDEX idx_order_items_order ON order_items(order_id);


-- ===================================
-- 3. ข้อมูลตัวอย่าง
-- ===================================

INSERT INTO roles (name, description, is_system) VALUES
('admin', 'ผู้ดูแลระบบ', true),
('user', 'ผู้ใช้งานทั่วไป', true);


-- รหัสผ่านทั้งหมดนี้คือ 'password123'
INSERT INTO users (username, email, first_name, last_name, password_hash, is_active) VALUES
(
    'admin',
    'admingoodtea@teashop.com',
    'Good',
    'Tea',
    '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2',
    true
),
(
    'user',
    'kkorya@teashop.com',
    'กอหญ้า',
    'อารมณ์ไม่ดี',
    '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2',
    true
);

-- 3. ผูก User กับ Role
-- (user_id 1 = 'admin', role_id 1 = 'admin')
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
(1, 1, 1);
-- (user_id 2 = 'user', role_id 2 = 'user')
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
(2, 2, 1);

-- 4. เพิ่ม Permissions
INSERT INTO permissions (name, resource, action) VALUES
('users:list', 'users', 'list'),
('users:read', 'users', 'read'),
('users:update:role', 'users', 'update_role'),
('products:create', 'products', 'create'),
('products:update', 'products', 'update'),
('products:delete', 'products', 'delete'),
('orders:list', 'orders', 'list'),
('orders:read', 'orders', 'read'),
('orders:update:status', 'orders', 'update_status');

-- 5. ผูก Role กับ Permission
INSERT INTO role_permissions (role_id, permission_id)
SELECT 1, id FROM permissions; 
-- select 1, id from permissions จะได้ permission ทั้งหมด


-- 6. เพิ่ม หมวดหมู่สินค้า

-- เพิ่มหมวดหมู่หลัก (parent_id เป็น NULL)
INSERT INTO categories (name, description, parent_id, image_url, is_featured) VALUES
('ชาใบ', 'ชาคุณภาพสูงจากแหล่งต่างๆ', NULL, 'images/categories/tea-leaves.jpg', true), -- (ID = 1)
('อุปกรณ์ชงชา', 'อุปกรณ์สำหรับประสบการณ์การชงชา', NULL, 'images/categories/accessories.jpg', true), -- (ID = 2)
('กาชงชา', 'กาชงชาดีไซน์สวยงาม', NULL, 'images/categories/tea-pots.jpg', false); -- (ID = 3)

-- เพิ่มหมวดหมู่ย่อย (Sub-categories) ภายใต้ "ชาใบ" (parent_id = 1)
INSERT INTO categories (name, description, parent_id, image_url, is_featured) VALUES
('ชาเขียว', 'ชาเขียวรสชาตินุ่มนวลจากญี่ปุ่นและจีน', 1, 'images/categories/green-tea.jpg', true),
('ชาอู่หลง', 'ชาอู่หลงกลิ่นหอมดอกไม้', 1, 'images/categories/oolong-tea.jpg', true),
('ชาดำ', 'ชาดำเข้มข้น รสชาติหนักแน่น', 1, 'images/categories/black-tea.jpg', false),
('ชาขาว', 'ชารสชาติเบาบาง ละเอียดอ่อน', 1, NULL, false);

-- เพิ่มหมวดหมู่ย่อย ภายใต้ "อุปกรณ์ชงชา" (parent_id = 2)
INSERT INTO categories (name, description, parent_id, image_url, is_featured) VALUES
('ที่กรองชา', 'ที่กรองชาสแตนเลสและซิลิโคน', 2, 'images/categories/strainers.jpg', false),
('ถ้วยชา', 'ถ้วยชาเซรามิกและแก้ว', 2, NULL, false);

-- 7. เพิ่ม สินค้า
INSERT INTO products (category_id, name, description, price, stock, image_url) VALUES
(5, 'ชาอู่หลงก้านอ่อน', 'ชาอู่หลงยอดนิยม กลิ่นหอมชื่นใจ รสชาตินุ่ม', 350.00, 100, 'images/products/oolong-soft-stem.jpg'), -- product_id = 1
(5, 'ชาอู่หลงไต้หวัน', 'ชาอู่หลงจากไต้หวันที่มีชื่อเสียง รสชาติกลมกล่อม', 400.00, 75, 'images/products/taiwan-oolong.jpg'); -- product_id = 2

-- สินค้าใน "ชาเขียว"
INSERT INTO products (category_id, name, description, price, stock, image_url) VALUES
(4, 'ชาเขียวมัทฉะ', 'ผงมัทฉะเกรดพรีเมียมจากญี่ปุ่น สำหรับชงดื่มหรือทำขนม', 500.00, 50, 'images/products/matcha-powder.jpg'), -- product_id = 3
(4, 'ชาเขียวโฮจิฉะ', 'ชาเขียวคั่ว กลิ่นหอมควันไฟ คาเฟอีนต่ำ', 280.00, 80, 'images/products/hojicha.jpg'), -- product_id = 4
(4, 'ชาเขียวเซนฉะ', 'ชาเขียวใบหยาบ รสชาติกลมกล่อม', 300.00, 60, 'images/products/sencha.jpg'); -- product_id = 5

-- สินค้าใน "ชาดำ"
INSERT INTO products (category_id, name, description, price, stock, image_url) VALUES
(6, 'ชาดำเอิร์ลเกรย์', 'ชาดำคลาสสิกผสมกลิ่นมะกรูด (Bergamot)', 320.00, 70, 'images/products/earl-grey.jpg'), -- product_id = 6
(6, 'ชาดำอังกฤษ', 'ชาดำรสเข้มข้น เหมาะสำหรับดื่มตอนเช้า', 300.00, 60, 'images/products/english-breakfast.jpg'); -- product_id = 7

-- สินค้าใน "กาชงชา"
INSERT INTO products (category_id, name, description, price, stock, image_url) VALUES
(3, 'กาชงชาดินเผา', 'กาชงชาสไตล์จีนแท้ ทำจากดินเผา Yixing', 1200.00, 20, 'images/products/yixing-teapot.jpg'), -- product_id = 8
(3, 'กาชงชากระเบื้องญี่ปุ่น', 'กาชงชาดีไซน์ญี่ปุ่น ทำจากกระเบื้องคุณภาพสูง', 950.00, 30, 'images/products/japanese-teapot.jpg'), -- product_id = 9
(3, 'กาชงชาแก้วทนความร้อน', 'กาชงชาแก้วใส ทนความร้อน เหมาะสำหรับชงชาเย็น', 800.00, 40, 'images/products/glass-teapot.jpg'); -- product_id = 10

-- สินค้าใน "ที่กรองชา"
INSERT INTO products (category_id, name, description, price, stock, image_url) VALUES
(8, 'ที่กรองชาสแตนเลส', 'ที่กรองชาทรงกลม ใช้งานง่าย ทนทาน', 150.00, 200, 'images/products/strainer-ball.jpg'); -- product_id = 11

-- สินค้าใน "ถ้วยชา"
INSERT INTO products (category_id, name, description, price, stock, image_url) VALUES
(9, 'ถ้วยชาเซรามิก', 'ถ้วยชาเซรามิกสไตล์ญี่ปุ่น', 250.00, 50, 'images/products/ceramic-cup.jpg'); -- product_id = 12

-- 8. เพิ่ม คำสั่งซื้อตัวอย่าง (Optional)
INSERT INTO orders (user_id, total_amount, status, customer_name, shipping_address)
VALUES 
(2, 1150.00, 'processing', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110'),
(2, 800.00, 'pending', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110');

-- รายการสินค้าในคำสั่งซื้อ 
INSERT INTO order_items (order_id, product_id, quantity, price_per_unit) VALUES 
(1, 1, 2, 350.00),  -- สินค้า: ชาอู่หลงก้านอ่อน จำนวน 2 แพ็ค
(1, 3, 1, 500.00),  -- สินค้า: ชาเขียวมัทฉะ จำนวน 1 แพ็ค
(2, 10, 1, 800.00); -- สินค้า: กาชงชาแก้วทนความร้อน จำนวน 1 ชิ้น
