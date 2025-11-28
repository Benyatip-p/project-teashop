DROP TABLE IF EXISTS
    order_items,
    orders,
    reviews,
    addresses,
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

-- ตาราง Addresses
CREATE TABLE addresses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    recipient_name VARCHAR(100),
    phone_number VARCHAR(20),
    address TEXT,
    province VARCHAR(100),
    postal_code VARCHAR(10),
    is_default BOOLEAN DEFAULT false
);

CREATE INDEX idx_addresses_user ON addresses(user_id);
CREATE INDEX idx_addresses_default ON addresses(user_id, is_default);

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

-- รูปแบบสินค้า (variants)
CREATE TABLE product_variants (
    id SERIAL PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    weight NUMERIC(10, 2) NOT NULL,
    price NUMERIC(10, 2) NOT NULL,
    stock INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_product_variants_product ON product_variants(product_id);

-- คำสั่งซื้อ
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    total_amount NUMERIC(10, 2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending', -- pending, paid, shipped, completed, cancelled, refunded
    tracking_number VARCHAR(100),
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
    variant_id INTEGER REFERENCES product_variants(id), -- Optional variant
    weight INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1, -- Quantity for stock management
    price_per_unit NUMERIC(10, 2) NOT NULL -- ราคา ณ ตอนที่ซื้อ
);
CREATE INDEX idx_order_items_order ON order_items(order_id);

-- รีวิวสินค้า
CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id),
    user_id INTEGER REFERENCES users(id),
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_reviews_product ON reviews(product_id);
CREATE INDEX idx_reviews_user ON reviews(user_id);


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

INSERT INTO users (username, email, first_name, last_name, password_hash, is_active, created_at) VALUES
('john', 'john@example.com', 'John', 'Doe', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', true, CURRENT_DATE - INTERVAL '2 months'),
('jane', 'jane@example.com', 'Jane', 'Smith', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', true, CURRENT_DATE - INTERVAL '2 months'),
('bob', 'bob@example.com', 'Bob', 'Wilson', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', true, CURRENT_DATE - INTERVAL '1 month'),
('alice', 'alice@example.com', 'Alice', 'Brown', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', true, CURRENT_DATE - INTERVAL '1 month'),
('charlie', 'charlie@example.com', 'Charlie', 'Davis', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', true, CURRENT_DATE - INTERVAL '1 month'),
('diana', 'diana@example.com', 'Diana', 'Evans', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', true, CURRENT_DATE - INTERVAL '3 months'),
('frank', 'frank@example.com', 'Frank', 'Garcia', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', true, CURRENT_DATE - INTERVAL '3 months');

-- 3. ผูก User กับ Role
-- (user_id 1 = 'admin', role_id 1 = 'admin')
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
(1, 1, 1);
-- (user_id 2 = 'user', role_id 2 = 'user')
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
(2, 2, 1);

INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
(3, 2, 1), (4, 2, 1), (5, 2, 1), (6, 2, 1), (7, 2, 1), (8, 2, 1), (9, 2, 1);

-- 4. เพิ่ม Addresses
INSERT INTO addresses (user_id, recipient_name, phone_number, address, province, postal_code, is_default) VALUES
(2, 'คุณวาริท อสังหา', '0812345678', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย', 'กรุงเทพฯ', '10110', true),
(2, 'คุณสมชาย ใจดี', '0898765432', '456 ถนนพระราม 9 แขวงห้วยขวาง เขตห้วยขวาง', 'กรุงเทพฯ', '10310', false);

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
('ชาขาว', 'ชารสชาติเบาบาง ละเอียดอ่อน', 1, 'images/categories/white-tea.jpg', false);

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

-- Variants สำหรับชาอู่หลงก้านอ่อน (product_id = 1)
INSERT INTO product_variants (product_id, weight, price, stock) VALUES
(1, 50.00, 175.00, 80),
(1, 100.00, 325.00, 60),
(1, 250.00, 700.00, 40);

-- Variants สำหรับชาอู่หลงไต้หวัน (product_id = 2)
INSERT INTO product_variants (product_id, weight, price, stock) VALUES
(2, 50.00, 200.00, 70),
(2, 100.00, 380.00, 50),
(2, 250.00, 850.00, 35);

-- Variants สำหรับชาเขียวมัทฉะ (product_id = 3)
INSERT INTO product_variants (product_id, weight, price, stock) VALUES
(3, 20.00, 250.00, 100),
(3, 50.00, 500.00, 50),
(3, 100.00, 900.00, 30);

-- Variants สำหรับชาเขียวโฮจิฉะ (product_id = 4)
INSERT INTO product_variants (product_id, weight, price, stock) VALUES
(4, 50.00, 140.00, 90),
(4, 100.00, 260.00, 70),
(4, 250.00, 580.00, 45);

-- Variants สำหรับชาเขียวเซนฉะ (product_id = 5)
INSERT INTO product_variants (product_id, weight, price, stock) VALUES
(5, 50.00, 150.00, 85),
(5, 100.00, 280.00, 65),
(5, 250.00, 620.00, 40);

-- Variants สำหรับชาดำเอิร์ลเกรย์ (product_id = 6)
INSERT INTO product_variants (product_id, weight, price, stock) VALUES
(6, 50.00, 160.00, 75),
(6, 100.00, 300.00, 55),
(6, 250.00, 650.00, 35);

-- Variants สำหรับชาดำอังกฤษ (product_id = 7)
INSERT INTO product_variants (product_id, weight, price, stock) VALUES
(7, 50.00, 150.00, 80),
(7, 100.00, 280.00, 60),
(7, 250.00, 600.00, 40);

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
INSERT INTO orders (user_id, total_amount, status, customer_name, shipping_address, tracking_number)
VALUES
-- User 2 (regular user) - multiple orders with different statuses
(2, 1150.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(2, 800.00, 'pending', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(2, 650.00, 'paid', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(2, 420.00, 'processing', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(2, 380.00, 'shipped', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', 'TH123456789'),
(2, 720.00, 'cancelled', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),

-- Other users with various statuses
(3, 500.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', NULL),
(3, 280.00, 'pending', 'John Doe', '456 Main St, Bangkok 10100', NULL),
(4, 750.00, 'shipped', 'Jane Smith', '789 Oak Ave, Bangkok 10200', 'TH987654321'),
(4, 320.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', NULL),
(5, 320.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', NULL),
(5, 150.00, 'cancelled', 'Bob Wilson', '321 Pine St, Bangkok 10300', NULL),
(6, 950.00, 'processing', 'Alice Brown', '654 Elm St, Bangkok 10400', NULL),
(6, 250.00, 'paid', 'Alice Brown', '654 Elm St, Bangkok 10400', NULL),
(7, 600.00, 'completed', 'Charlie Davis', '987 Maple St, Bangkok 10500', NULL),
(7, 1200.00, 'shipped', 'Charlie Davis', '987 Maple St, Bangkok 10500', 'TH555666777'),
(8, 1200.00, 'pending', 'Diana Evans', '147 Birch St, Bangkok 10600', NULL),
(8, 300.00, 'processing', 'Diana Evans', '147 Birch St, Bangkok 10600', NULL),
(9, 850.00, 'completed', 'Frank Garcia', '258 Cedar St, Bangkok 10700', NULL),
(9, 400.00, 'paid', 'Frank Garcia', '258 Cedar St, Bangkok 10700', NULL),

-- Additional orders for better testing
(3, 900.00, 'shipped', 'John Doe', '456 Main St, Bangkok 10100', 'TH111222333'),
(4, 180.00, 'cancelled', 'Jane Smith', '789 Oak Ave, Bangkok 10200', NULL),
(5, 550.00, 'processing', 'Bob Wilson', '321 Pine St, Bangkok 10300', NULL),
(6, 120.00, 'completed', 'Alice Brown', '654 Elm St, Bangkok 10400', NULL),
(7, 800.00, 'paid', 'Charlie Davis', '987 Maple St, Bangkok 10500', NULL);

-- รายการสินค้าในคำสั่งซื้อ
INSERT INTO order_items (order_id, product_id, weight, quantity, price_per_unit) VALUES
-- Order 1 (user 2, completed)
(1, 1, 2, 2, 350.00),  -- ชาอู่หลงก้านอ่อน x2
(1, 3, 1, 1, 500.00),  -- ชาเขียวมัทฉะ x1

-- Order 2 (user 2, pending)
(2, 10, 1, 1, 800.00), -- กาชงชาแก้วทนความร้อน x1

-- Order 3 (user 2, paid)
(3, 4, 1, 1, 280.00),  -- ชาเขียวโฮจิฉะ x1
(3, 6, 1, 1, 320.00),  -- ชาดำเอิร์ลเกรย์ x1

-- Order 4 (user 2, processing)
(4, 6, 1, 1, 320.00),  -- ชาดำเอิร์ลเกรย์ x1
(4, 5, 1, 1, 300.00),  -- ชาเขียวเซนฉะ x1

-- Order 5 (user 2, shipped)
(5, 7, 1, 1, 300.00),  -- ชาดำอังกฤษ x1
(5, 11, 1, 1, 150.00), -- ที่กรองชาสแตนเลส x1

-- Order 6 (user 2, cancelled)
(6, 8, 1, 1, 950.00),  -- กาชงชากระเบื้องญี่ปุ่น x1

-- Order 7 (user 3, completed)
(7, 3, 1, 1, 500.00),  -- ชาเขียวมัทฉะ x1

-- Order 8 (user 3, pending)
(8, 4, 1, 1, 280.00),  -- ชาเขียวโฮจิฉะ x1

-- Order 9 (user 4, shipped)
(9, 8, 1, 1, 950.00),  -- กาชงชากระเบื้องญี่ปุ่น x1

-- Order 10 (user 4, completed)
(10, 6, 1, 1, 320.00), -- ชาดำเอิร์ลเกรย์ x1

-- Order 11 (user 5, completed)
(11, 6, 1, 1, 320.00), -- ชาดำเอิร์ลเกรย์ x1

-- Order 12 (user 5, cancelled)
(12, 11, 1, 1, 150.00), -- ที่กรองชาสแตนเลส x1

-- Order 13 (user 6, processing)
(13, 8, 1, 1, 950.00), -- กาชงชากระเบื้องญี่ปุ่น x1

-- Order 14 (user 6, paid)
(14, 12, 1, 1, 250.00), -- ถ้วยชาเซรามิก x1

-- Order 15 (user 7, completed)
(15, 5, 2, 2, 300.00), -- ชาเขียวเซนฉะ x2

-- Order 16 (user 7, shipped)
(16, 9, 1, 1, 1200.00), -- กาชงชาดินเผา x1

-- Order 17 (user 8, pending)
(17, 9, 1, 1, 1200.00), -- กาชงชาดินเผา x1

-- Order 18 (user 8, processing)
(18, 12, 1, 1, 250.00), -- ถ้วยชาเซรามิก x1

-- Order 19 (user 9, completed)
(19, 7, 2, 2, 300.00), -- ชาดำอังกฤษ x2
(19, 11, 1, 1, 250.00), -- ที่กรองชาสแตนเลส x1

-- Order 20 (user 9, paid)
(20, 10, 1, 1, 800.00), -- กาชงชาแก้วทนความร้อน x1

-- Order 21 (user 3, shipped)
(21, 8, 1, 1, 950.00),  -- กาชงชากระเบื้องญี่ปุ่น x1

-- Order 22 (user 4, cancelled)
(22, 12, 1, 1, 250.00), -- ถ้วยชาเซรามิก x1

-- Order 23 (user 5, processing)
(23, 7, 1, 1, 300.00),  -- ชาดำอังกฤษ x1
(23, 4, 1, 1, 280.00),  -- ชาเขียวโฮจิฉะ x1

-- Order 24 (user 6, completed)
(24, 11, 1, 1, 150.00), -- ที่กรองชาสแตนเลส x1

-- Order 25 (user 7, paid)
(25, 10, 1, 1, 800.00); -- กาชงชาแก้วทนความร้อน x1

-- ===================================
-- Additional Orders for Sales History Testing
-- ===================================

-- Orders in 2023
INSERT INTO orders (user_id, total_amount, status, customer_name, shipping_address, created_at) VALUES
(2, 500.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', '2023-01-15 10:30:00'),
(3, 750.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', '2023-02-20 14:15:00'),
(4, 320.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', '2023-03-10 09:45:00'),
(5, 600.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', '2023-04-05 16:20:00'),
(6, 450.00, 'completed', 'Alice Brown', '654 Elm St, Bangkok 10400', '2023-05-12 11:30:00'),
(7, 800.00, 'completed', 'Charlie Davis', '987 Maple St, Bangkok 10500', '2023-06-18 13:45:00'),
(8, 350.00, 'completed', 'Diana Evans', '147 Birch St, Bangkok 10600', '2023-07-25 15:10:00'),
(9, 550.00, 'completed', 'Frank Garcia', '258 Cedar St, Bangkok 10700', '2023-08-08 10:55:00'),
(2, 420.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', '2023-09-14 12:40:00'),
(3, 680.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', '2023-10-22 14:25:00'),
(4, 290.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', '2023-11-30 16:15:00'),
(5, 720.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', '2023-12-05 11:50:00');

-- Orders in 2024
INSERT INTO orders (user_id, total_amount, status, customer_name, shipping_address, created_at) VALUES
(6, 380.00, 'completed', 'Alice Brown', '654 Elm St, Bangkok 10400', '2024-01-08 09:30:00'),
(7, 650.00, 'completed', 'Charlie Davis', '987 Maple St, Bangkok 10500', '2024-02-14 13:20:00'),
(8, 480.00, 'completed', 'Diana Evans', '147 Birch St, Bangkok 10600', '2024-03-19 15:45:00'),
(9, 520.00, 'completed', 'Frank Garcia', '258 Cedar St, Bangkok 10700', '2024-04-25 10:15:00'),
(2, 610.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', '2024-05-02 14:30:00'),
(3, 430.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', '2024-06-11 11:25:00'),
(4, 780.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', '2024-07-16 16:40:00'),
(5, 360.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', '2024-08-21 12:55:00'),
(6, 590.00, 'completed', 'Alice Brown', '654 Elm St, Bangkok 10400', '2024-09-28 09:10:00'),
(7, 710.00, 'completed', 'Charlie Davis', '987 Maple St, Bangkok 10500', '2024-10-03 15:35:00'),
(8, 440.00, 'completed', 'Diana Evans', '147 Birch St, Bangkok 10600', '2024-11-09 13:50:00'),
(9, 670.00, 'completed', 'Frank Garcia', '258 Cedar St, Bangkok 10700', '2024-12-15 10:20:00');

-- Orders in 2025 (current year) - monthly distribution
INSERT INTO orders (user_id, total_amount, status, customer_name, shipping_address, created_at) VALUES
-- January 2025
(2, 550.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', '2025-01-05 10:30:00'),
(3, 320.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', '2025-01-12 14:15:00'),
(4, 480.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', '2025-01-18 09:45:00'),
(5, 290.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', '2025-01-25 16:20:00'),

-- February 2025
(6, 650.00, 'completed', 'Alice Brown', '654 Elm St, Bangkok 10400', '2025-02-03 11:30:00'),
(7, 420.00, 'completed', 'Charlie Davis', '987 Maple St, Bangkok 10500', '2025-02-10 13:45:00'),
(8, 380.00, 'completed', 'Diana Evans', '147 Birch St, Bangkok 10600', '2025-02-17 15:10:00'),
(9, 720.00, 'completed', 'Frank Garcia', '258 Cedar St, Bangkok 10700', '2025-02-24 10:55:00'),

-- March 2025
(2, 510.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', '2025-03-07 12:40:00'),
(3, 680.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', '2025-03-14 14:25:00'),
(4, 440.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', '2025-03-21 16:15:00'),
(5, 590.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', '2025-03-28 11:50:00'),

-- April 2025
(6, 360.00, 'completed', 'Alice Brown', '654 Elm St, Bangkok 10400', '2025-04-04 09:30:00'),
(7, 780.00, 'completed', 'Charlie Davis', '987 Maple St, Bangkok 10500', '2025-04-11 13:20:00'),
(8, 520.00, 'completed', 'Diana Evans', '147 Birch St, Bangkok 10600', '2025-04-18 15:45:00'),
(9, 430.00, 'completed', 'Frank Garcia', '258 Cedar St, Bangkok 10700', '2025-04-25 10:15:00'),

-- May 2025
(2, 610.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', '2025-05-02 14:30:00'),
(3, 350.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', '2025-05-09 11:25:00'),
(4, 710.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', '2025-05-16 16:40:00'),
(5, 480.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', '2025-05-23 12:55:00'),

-- June 2025
(6, 540.00, 'completed', 'Alice Brown', '654 Elm St, Bangkok 10400', '2025-06-01 09:10:00'),
(7, 670.00, 'completed', 'Charlie Davis', '987 Maple St, Bangkok 10500', '2025-06-08 15:35:00'),
(8, 390.00, 'completed', 'Diana Evans', '147 Birch St, Bangkok 10600', '2025-06-15 13:50:00'),
(9, 580.00, 'completed', 'Frank Garcia', '258 Cedar St, Bangkok 10700', '2025-06-22 10:20:00'),

-- July 2025
(2, 460.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', '2025-07-03 12:15:00'),
(3, 730.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', '2025-07-10 14:40:00'),
(4, 410.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', '2025-07-17 16:25:00'),
(5, 630.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', '2025-07-24 11:30:00'),

-- August 2025
(6, 370.00, 'completed', 'Alice Brown', '654 Elm St, Bangkok 10400', '2025-08-02 09:45:00'),
(7, 690.00, 'completed', 'Charlie Davis', '987 Maple St, Bangkok 10500', '2025-08-09 13:55:00'),
(8, 450.00, 'completed', 'Diana Evans', '147 Birch St, Bangkok 10600', '2025-08-16 15:20:00'),
(9, 520.00, 'completed', 'Frank Garcia', '258 Cedar St, Bangkok 10700', '2025-08-23 10:35:00'),

-- September 2025
(2, 580.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', '2025-09-04 12:50:00'),
(3, 340.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', '2025-09-11 14:15:00'),
(4, 760.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', '2025-09-18 16:30:00'),
(5, 410.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', '2025-09-25 11:45:00'),

-- October 2025
(6, 620.00, 'completed', 'Alice Brown', '654 Elm St, Bangkok 10400', '2025-10-02 09:20:00'),
(7, 380.00, 'completed', 'Charlie Davis', '987 Maple St, Bangkok 10500', '2025-10-09 13:35:00'),
(8, 710.00, 'completed', 'Diana Evans', '147 Birch St, Bangkok 10600', '2025-10-16 15:50:00'),
(9, 470.00, 'completed', 'Frank Garcia', '258 Cedar St, Bangkok 10700', '2025-10-23 10:05:00'),

-- November 2025 (up to current date)
(2, 530.00, 'completed', 'คุณวาริท อสังหา', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', '2025-11-01 12:10:00'),
(3, 690.00, 'completed', 'John Doe', '456 Main St, Bangkok 10100', '2025-11-08 14:25:00'),
(4, 420.00, 'completed', 'Jane Smith', '789 Oak Ave, Bangkok 10200', '2025-11-15 16:40:00'),
(5, 560.00, 'completed', 'Bob Wilson', '321 Pine St, Bangkok 10300', '2025-11-22 11:55:00');

-- ===================================
-- Order Items for Historical Orders
-- ===================================

-- 2023 Orders (orders 26-37)
INSERT INTO order_items (order_id, product_id, weight, quantity, price_per_unit) VALUES
(26, 1, 1, 1, 350.00), (26, 3, 1, 1, 500.00),
(27, 8, 1, 1, 950.00),
(28, 6, 1, 1, 320.00),
(29, 5, 2, 2, 300.00),
(30, 4, 1, 1, 280.00), (30, 7, 1, 1, 300.00),
(31, 9, 1, 1, 1200.00),
(32, 2, 1, 1, 400.00),
(33, 10, 1, 1, 800.00),
(34, 11, 1, 1, 150.00), (34, 12, 1, 1, 250.00),
(35, 3, 1, 1, 500.00),
(36, 6, 1, 1, 320.00),
(37, 7, 2, 2, 300.00);

-- 2024 Orders (orders 38-49)
INSERT INTO order_items (order_id, product_id, weight, quantity, price_per_unit) VALUES
(38, 4, 1, 1, 280.00), (38, 5, 1, 1, 300.00),
(39, 9, 1, 1, 1200.00),
(40, 2, 1, 1, 400.00),
(41, 8, 1, 1, 950.00),
(42, 1, 1, 1, 350.00), (42, 6, 1, 1, 320.00),
(43, 10, 1, 1, 800.00),
(44, 7, 1, 1, 300.00), (44, 11, 1, 1, 150.00),
(45, 3, 1, 1, 500.00),
(46, 5, 1, 1, 300.00),
(47, 9, 1, 1, 1200.00),
(48, 4, 1, 1, 280.00),
(49, 6, 2, 2, 320.00);

-- 2025 Orders (orders 50-81)
INSERT INTO order_items (order_id, product_id, weight, quantity, price_per_unit) VALUES
-- January 2025
(50, 1, 1, 1, 350.00), (50, 3, 1, 1, 500.00),
(51, 6, 1, 1, 320.00),
(52, 4, 1, 1, 280.00), (52, 7, 1, 1, 300.00),
(53, 11, 1, 1, 150.00), (53, 12, 1, 1, 250.00),

-- February 2025
(54, 8, 1, 1, 950.00),
(55, 5, 1, 1, 300.00), (55, 9, 1, 1, 1200.00),
(56, 2, 1, 1, 400.00),
(57, 10, 1, 1, 800.00),

-- March 2025
(58, 1, 1, 1, 350.00), (58, 6, 1, 1, 320.00),
(59, 3, 1, 1, 500.00),
(60, 7, 1, 1, 300.00), (60, 11, 1, 1, 150.00),
(61, 4, 1, 1, 280.00), (61, 5, 1, 1, 300.00),

-- April 2025
(62, 12, 1, 1, 250.00), (62, 11, 1, 1, 150.00),
(63, 9, 1, 1, 1200.00),
(64, 2, 1, 1, 400.00),
(65, 8, 1, 1, 950.00),

-- May 2025
(66, 1, 1, 1, 350.00), (66, 3, 1, 1, 500.00),
(67, 6, 1, 1, 320.00),
(68, 10, 1, 1, 800.00),
(69, 7, 1, 1, 300.00), (69, 11, 1, 1, 150.00),

-- June 2025
(70, 4, 1, 1, 280.00), (70, 5, 1, 1, 300.00),
(71, 9, 1, 1, 1200.00),
(72, 2, 1, 1, 400.00),
(73, 12, 1, 1, 250.00),

-- July 2025
(74, 1, 1, 1, 350.00), (74, 6, 1, 1, 320.00),
(75, 3, 1, 1, 500.00),
(76, 7, 1, 1, 300.00), (76, 11, 1, 1, 150.00),
(77, 8, 1, 1, 950.00),

-- August 2025
(78, 5, 1, 1, 300.00), (78, 10, 1, 1, 800.00),
(79, 9, 1, 1, 1200.00),
(80, 2, 1, 1, 400.00),
(81, 4, 1, 1, 280.00), (81, 6, 1, 1, 320.00),

-- September 2025
(82, 1, 1, 1, 350.00), (82, 3, 1, 1, 500.00),
(83, 7, 1, 1, 300.00), (83, 11, 1, 1, 150.00),
(84, 10, 1, 1, 800.00),
(85, 5, 1, 1, 300.00), (85, 12, 1, 1, 250.00),

-- October 2025
(86, 8, 1, 1, 950.00),
(87, 2, 1, 1, 400.00),
(88, 9, 1, 1, 1200.00),
(89, 6, 1, 1, 320.00), (89, 11, 1, 1, 150.00),

-- November 2025
(90, 1, 1, 1, 350.00), (90, 4, 1, 1, 280.00),
(91, 3, 1, 1, 500.00),
(92, 7, 1, 1, 300.00), (92, 10, 1, 1, 800.00),
(93, 5, 1, 1, 300.00), (93, 12, 1, 1, 250.00);

-- เพิ่มรีวิวตัวอย่าง
INSERT INTO reviews (product_id, user_id, rating) VALUES
(1, 2, 5),  -- ชาอู่หลงก้านอ่อน
(2, 2, 4),  -- ชาอู่หลงไต้หวัน
(3, 2, 5),  -- ชาเขียวมัทฉะ
(1, 3, 4),  -- ชาอู่หลงก้านอ่อน
(4, 5, 3),  -- ชาเขียวโฮจิฉะ
(5, 6, 4),  -- ชาเขียวเซนฉะ
(6, 7, 5),  -- ชาดำเอิร์ลเกรย์
(7, 8, 4),  -- ชาดำอังกฤษ
(8, 9, 5),  -- กาชงชาดินเผา
(9, 3, 4),  -- กาชงชากระเบื้องญี่ปุ่น
(10, 4, 5); -- กาชงชาแก้วทนความร้อน
