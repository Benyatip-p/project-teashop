-- Drop existing tables in reverse dependency order
DROP TABLE IF EXISTS
    order_items,
    orders,
    reviews,
    addresses,
    product_variants,
    products,
    categories,
    audit_logs,
    refresh_tokens,
    role_permissions,
    permissions,
    user_roles,
    roles,
    users,
    product_attribute_config
CASCADE;

-- ===================================
-- 1. AUTHENTICATION & USER MANAGEMENT
-- ===================================

-- Users table
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

-- Create indexes for users
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active);

-- Addresses table
CREATE TABLE addresses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    address TEXT NOT NULL,
    province VARCHAR(100) NOT NULL,
    postal_code VARCHAR(10) NOT NULL,
    is_default BOOLEAN DEFAULT FALSE
);

-- Create indexes for addresses
CREATE INDEX idx_addresses_user ON addresses(user_id);
CREATE INDEX idx_addresses_default ON addresses(user_id, is_default);

-- Roles table
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for roles
CREATE INDEX idx_roles_name ON roles(name);

-- User-Role assignments
CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

-- Create indexes for user_roles
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);

-- Permissions table
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for permissions
CREATE INDEX idx_permissions_name ON permissions(name);

-- Role-Permission assignments
CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(500) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    replaced_by VARCHAR(500)
);

-- Create index for refresh tokens
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);

-- Audit logs table
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

-- Create index for audit logs
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);

-- ===================================
-- 2. PRODUCT MANAGEMENT
-- ===================================

-- Categories table
CREATE TABLE categories (
    id SERIAL PRIMARY KEY,
    parent_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    image_url TEXT,
    is_featured BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index for categories
CREATE INDEX idx_categories_parent ON categories(parent_id);

-- Products table
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    image_url TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for products
CREATE INDEX idx_products_category ON products(category_id);
CREATE INDEX idx_products_name ON products(name);

-- Product variants table
CREATE TABLE product_variants (
    id SERIAL PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    weight NUMERIC(10, 2),  -- NULL for accessories
    price NUMERIC(10, 2) NOT NULL,
    stock INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index for product variants
CREATE INDEX idx_product_variants_product ON product_variants(product_id);

-- Product Attribute Configuration table
CREATE TABLE product_attribute_config (
    id SERIAL PRIMARY KEY,
    category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
    schema JSONB NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(category_id)
);

-- Create index for product attribute config
CREATE INDEX idx_product_attribute_config_category_id ON product_attribute_config(category_id);

-- ===================================
-- 3. ORDER MANAGEMENT
-- ===================================

-- Orders table
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    total_amount NUMERIC(10, 2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    tracking_number VARCHAR(100),
    customer_name VARCHAR(100),
    shipping_address TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for orders
CREATE INDEX idx_orders_user ON orders(user_id);
CREATE INDEX idx_orders_status ON orders(status);

-- Order items table
CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id),
    variant_id INTEGER NOT NULL REFERENCES product_variants(id),
    weight INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    price_per_unit NUMERIC(10, 2) NOT NULL
);

-- Create index for order items
CREATE INDEX idx_order_items_order ON order_items(order_id);

-- Reviews table
CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id),
    user_id INTEGER REFERENCES users(id),
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for reviews
CREATE INDEX idx_reviews_product ON reviews(product_id);
CREATE INDEX idx_reviews_user ON reviews(user_id);


-- ===================================
-- SAMPLE DATA
-- ===================================

-- Insert roles
INSERT INTO roles (name, description, is_system) VALUES
('admin', 'Administrator with full access', TRUE),
('user', 'Regular user', TRUE);

-- Insert users (all passwords are 'password123')
INSERT INTO users (username, email, first_name, last_name, password_hash, is_active) VALUES
('admin', 'admingoodtea@teashop.com', 'Good', 'Tea', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', TRUE),
('user', 'kkorya@teashop.com', 'กอหญ้า', 'อารมณ์ไม่ดี', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', TRUE);

-- Insert additional users
INSERT INTO users (username, email, first_name, last_name, password_hash, is_active, created_at) VALUES
('john', 'john@example.com', 'John', 'Doe', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', TRUE, CURRENT_DATE - INTERVAL '2 months'),
('jane', 'jane@example.com', 'Jane', 'Smith', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', TRUE, CURRENT_DATE - INTERVAL '2 months'),
('bob', 'bob@example.com', 'Bob', 'Wilson', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', TRUE, CURRENT_DATE - INTERVAL '1 month'),
('alice', 'alice@example.com', 'Alice', 'Brown', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', TRUE, CURRENT_DATE - INTERVAL '1 month'),
('charlie', 'charlie@example.com', 'Charlie', 'Davis', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', TRUE, CURRENT_DATE - INTERVAL '1 month'),
('diana', 'diana@example.com', 'Diana', 'Evans', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', TRUE, CURRENT_DATE - INTERVAL '3 months'),
('frank', 'frank@example.com', 'Frank', 'Garcia', '$2a$12$SGT5hg1kZVzPf4tJilY.1ODqqk8C3Vnf.ia9uW3p7Yalh2PT3PCu2', TRUE, CURRENT_DATE - INTERVAL '3 months');

-- Assign roles to users
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
(1, 1, 1), -- admin user
(2, 2, 1); -- regular user

-- Assign user role to all other users
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
(3, 2, 1), (4, 2, 1), (5, 2, 1), (6, 2, 1), (7, 2, 1), (8, 2, 1), (9, 2, 1);

-- Insert permissions
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

-- Assign all permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT 1, id FROM permissions;

-- Insert addresses
INSERT INTO addresses (user_id, recipient_name, phone_number, address, province, postal_code, is_default) VALUES
(2, 'คุณกอหญ้า อารมณ์ไม่ดี', '0812345678', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย', 'กรุงเทพฯ', '10110', TRUE),
(2, 'คุณสมชาย ใจดี', '0898765432', '456 ถนนพระราม 9 แขวงห้วยขวาง เขตห้วยขวาง', 'กรุงเทพฯ', '10310', FALSE),
(3, 'John Doe', '0912233445', '12/99 หมู่บ้านกรีนการ์เด้น ถนนสุขุมวิท ตำบลศรีราชา อำเภอศรีราชา', 'ชลบุรี', '20110', TRUE),
(3, 'John Doe', '0915566778', '88/7 ถนนเลี่ยงเมือง ตำบลในเมือง อำเภอเมือง', 'ขอนแก่น', '40000', FALSE),
(4, 'Jane Smith', '0998877665', '45/3 ถนนมิตรภาพ ตำบลปากช่อง อำเภอปากช่อง', 'นครราชสีมา', '30130', TRUE),
(4, 'Jane Smith', '0985566774', '77/22 หมู่ 4 ตำบลบางเมือง อำเภอเมือง', 'สมุทรปราการ', '10270', FALSE);

-- Insert categories
INSERT INTO categories (name, description, parent_id, image_url, is_featured) VALUES
('ชาใบ', 'ชาคุณภาพสูงจากแหล่งต่างๆ', NULL, 'images/categories/tea-leaves.jpg', TRUE),
('อุปกรณ์ชงชา', 'อุปกรณ์สำหรับประสบการณ์การชงชา', NULL, 'images/categories/accessories.jpg', TRUE),
('กาชงชา', 'กาชงชาดีไซน์สวยงาม', NULL, 'images/categories/tea-pots.jpg', FALSE);

-- Insert subcategories
INSERT INTO categories (name, description, parent_id, image_url, is_featured) VALUES
('ชาเขียว', 'ชาเขียวรสชาตินุ่มนวลจากญี่ปุ่นและจีน', 1, 'images/categories/green-tea.jpg', TRUE),
('ชาอู่หลง', 'ชาอู่หลงกลิ่นหอมดอกไม้', 1, 'images/categories/oolong-tea.jpg', TRUE),
('ชาดำ', 'ชาดำเข้มข้น รสชาติหนักแน่น', 1, 'images/categories/black-tea.jpg', FALSE),
('ชาขาว', 'ชารสชาติเบาบาง ละเอียดอ่อน', 1, 'images/categories/white-tea.jpg', FALSE),
('ที่กรองชา', 'ที่กรองชาสแตนเลสและซิลิโคน', 2, 'images/categories/strainers.jpg', FALSE),
('ถ้วยชา', 'ถ้วยชาเซรามิกและแก้ว', 2, NULL, FALSE);

-- Insert products
INSERT INTO products (category_id, name, description, image_url) VALUES
(5, 'ชาอู่หลงก้านอ่อน', 'ชาอู่หลงยอดนิยม กลิ่นหอมชื่นใจ รสชาตินุ่ม', 'images/products/oolong-soft-stem.jpg'),
(5, 'ชาอู่หลงไต้หวัน', 'ชาอู่หลงจากไต้หวันที่มีชื่อเสียง รสชาติกลมกล่อม', 'images/products/taiwan-oolong.jpg'),
(4, 'ชาเขียวมัทฉะ', 'ผงมัทฉะเกรดพรีเมียมจากญี่ปุ่น สำหรับชงดื่มหรือทำขนม', 'images/products/matcha-powder.jpg'),
(4, 'ชาเขียวโฮจิฉะ', 'ชาเขียวคั่ว กลิ่นหอมควันไฟ คาเฟอีนต่ำ', 'images/products/hojicha.jpg'),
(4, 'ชาเขียวเซนฉะ', 'ชาเขียวใบหยาบ รสชาติกลมกล่อม', 'images/products/sencha.jpg'),
(6, 'ชาดำเอิร์ลเกรย์', 'ชาดำคลาสสิกผสมกลิ่นมะกรูด (Bergamot)', 'images/products/earl-grey.jpg'),
(6, 'ชาดำอังกฤษ', 'ชาดำรสเข้มข้น เหมาะสำหรับดื่มตอนเช้า', 'images/products/english-breakfast.jpg'),
(3, 'กาชงชาดินเผา', 'กาชงชาสไตล์จีนแท้ ทำจากดินเผา Yixing', 'images/products/yixing-teapot.jpg'),
(3, 'กาชงชากระเบื้องญี่ปุ่น', 'กาชงชาดีไซน์ญี่ปุ่น ทำจากกระเบื้องคุณภาพสูง', 'images/products/japanese-teapot.jpg'),
(3, 'กาชงชาแก้วทนความร้อน', 'กาชงชาแก้วใส ทนความร้อน เหมาะสำหรับชงชาเย็น', 'images/products/glass-teapot.jpg'),
(8, 'ที่กรองชาสแตนเลส', 'ที่กรองชาทรงกลม ใช้งานง่าย ทนทาน', 'images/products/strainer-ball.jpg'),
(9, 'ถ้วยชาเซรามิก', 'ถ้วยชาเซรามิกสไตล์ญี่ปุ่น', 'images/products/ceramic-cup.jpg');

-- Insert product variants
INSERT INTO product_variants (product_id, weight, price, stock) VALUES
-- Oolong teas
(1, 50.00, 175.00, 80), (1, 100.00, 325.00, 60), (1, 250.00, 700.00, 40),
(2, 50.00, 200.00, 70), (2, 100.00, 380.00, 50), (2, 250.00, 850.00, 35),
-- Green teas
(3, 20.00, 250.00, 100), (3, 50.00, 500.00, 50), (3, 100.00, 900.00, 30),
(4, 50.00, 140.00, 90), (4, 100.00, 260.00, 70), (4, 250.00, 580.00, 45),
(5, 50.00, 150.00, 85), (5, 100.00, 280.00, 65), (5, 250.00, 620.00, 40),
-- Black teas
(6, 50.00, 160.00, 75), (6, 100.00, 300.00, 55), (6, 250.00, 650.00, 35),
(7, 50.00, 150.00, 80), (7, 100.00, 280.00, 60), (7, 250.00, 600.00, 40),
-- Teapots (accessories - no weight)
(8, NULL, 1200.00, 20), (9, NULL, 950.00, 30), (10, NULL, 800.00, 40),
-- Accessories
(11, NULL, 150.00, 200), (12, NULL, 250.00, 50);

-- Insert product attribute configurations
INSERT INTO product_attribute_config (category_id, schema) VALUES
(1, '{
  "fields": [
    {"key": "origin", "label": "แหล่งที่มา", "type": "text", "placeholder": "ระบุชื่อไร่ หรือ จังหวัด"},
    {"key": "special_production_method", "label": "วิธีการผลิตพิเศษ", "type": "textarea", "placeholder": "เช่น คั่วด้วยถ่านไม้ลำไย, หมักในถังไม้โอ๊ค"},
    {"key": "highlights", "label": "จุดเด่นของชา", "type": "tags", "placeholder": "พิมพ์แล้วกด Enter เพื่อเพิ่ม (เช่น ชุ่มคอ, กลิ่นหอม)"},
    {"key": "mood_flavor_notes", "label": "Mood & Flavor Notes", "type": "tags", "placeholder": "เช่น Relaxing, Nutty, Floral"}
  ]
}'),
(2, '{
  "fields": [
    {"key": "origin", "label": "แหล่งที่มา", "type": "text"},
    {"key": "special_production_method", "label": "วิธีการผลิตพิเศษ", "type": "textarea"},
    {"key": "highlights", "label": "จุดเด่น", "type": "tags"}
  ]
}'),
(3, '{
  "fields": [
    {"key": "origin", "label": "แหล่งที่มา", "type": "text"},
    {"key": "special_production_method", "label": "วิธีการผลิตพิเศษ", "type": "textarea"},
    {"key": "highlights", "label": "จุดเด่น", "type": "tags"}
  ]
}');

-- Insert sample orders
INSERT INTO orders (user_id, total_amount, status, customer_name, shipping_address, tracking_number) VALUES
(2, 900.00, 'pending', 'คุณกอหญ้า อารมณ์ไม่ดี', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(2, 750.00, 'paid', 'คุณกอหญ้า อารมณ์ไม่ดี', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(2, 1200.00, 'processing', 'คุณกอหญ้า อารมณ์ไม่ดี', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(2, 680.00, 'shipped', 'คุณกอหญ้า อารมณ์ไม่ดี', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', 'TH202500001'),
(2, 1450.00, 'completed', 'คุณกอหญ้า อารมณ์ไม่ดี', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(2, 540.00, 'cancelled', 'คุณกอหญ้า อารมณ์ไม่ดี', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL);

INSERT INTO orders (user_id, total_amount, status, customer_name, shipping_address, tracking_number) VALUES
(3, 820.00, 'pending', 'John Doe', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(3, 690.00, 'paid', 'John Doe', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(3, 940.00, 'processing', 'John Doe', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(3, 780.00, 'shipped', 'John Doe', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', 'TH202500002'),
(3, 1300.00, 'completed', 'John Doe', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(3, 410.00, 'cancelled', 'John Doe', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL);

INSERT INTO orders (user_id, total_amount, status, customer_name, shipping_address, tracking_number) VALUES
(4, 760.00, 'pending', 'Jane Smith', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(4, 540.00, 'paid', 'Jane Smith', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(4, 880.00, 'processing', 'Jane Smith', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(4, 620.00, 'shipped', 'Jane Smith', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', 'TH202500003'),
(4, 990.00, 'completed', 'Jane Smith', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL),
(4, 350.00, 'cancelled', 'Jane Smith', '123 ถนนสุขุมวิท แขวงคลองตัน เขตคลองเตย กรุงเทพฯ 10110', NULL);


-- Insert order items with proper variant references
INSERT INTO order_items (order_id, product_id, variant_id, weight, quantity, price_per_unit) VALUES
(1, 1, 1, 2, 2, 350.00), (1, 3, 4, 1, 1, 500.00),
(2, 10, 24, 1, 1, 800.00),
(3, 4, 7, 1, 1, 280.00), (3, 6, 13, 1, 1, 320.00),
(4, 6, 13, 1, 1, 320.00), (4, 5, 10, 1, 1, 300.00),
(5, 7, 16, 1, 1, 300.00), (5, 11, 25, 1, 1, 150.00),
(6, 9, 23, 1, 1, 950.00);

-- Insert sample reviews
INSERT INTO reviews (product_id, user_id, rating) VALUES
(1, 2, 5), (2, 2, 4), (3, 2, 5), (1, 3, 4), (4, 5, 3),
(5, 6, 4), (6, 7, 5), (7, 8, 4), (8, 9, 5), (9, 3, 4), (10, 4, 5);
