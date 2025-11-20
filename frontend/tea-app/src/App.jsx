import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

// Components
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import NotFound from './components/Notfound';
import { ShopProvider } from "./context/ShopContext";
import ProtectedRoute from "./components/ProtectedRoute";

// Pages
import Homepage from './pages/Homepage';
import ContactPage from './pages/Contactpage';
import Aboutpage from './pages/Aboutpage';
import Productpage from './pages/Productpage';
import Favoritepage from './pages/Favoritepage';
import Cartpage from './pages/Cartpage';
import Profilepage from './pages/Profilepage';
import ProductDetailpage from './pages/ProductDetailpage';
import LoginPage from './pages/LoginPage';
import DeleteTeaPage from './pages/DeleteTeaPage';
import EditTeaPage from './pages/EditTeaPage/EditTeaPage';
import AdminDashboardPage from './pages/AdminDashboard/AdminDashboard';
import AdminProductPage from './pages/AdminDashboard/AdminProductPage';

// Layout สำหรับ Public Pages
const PublicLayout = ({ children }) => (
  <div className="flex flex-col min-h-screen">
    <Navbar />
    <main className="flex-grow bg-gray-50">{children}</main>
    <Footer />
  </div>
);

// Layout สำหรับ Login Page
const LoginLayout = ({ children }) => (
  <div className="flex flex-col min-h-screen">
    <Navbar />
    <main className="flex-grow bg-gray-50">{children}</main>
  </div>
);

// Layout สำหรับ Admin Page (ไม่มี Navbar/ Footer)
const AdminLayout = ({ children }) => <>{children}</>;

function App() {
  return (
    <ShopProvider>
      <Router>
        <Routes>
          {/* Login Page */}
          <Route
            path="/login"
            element={
              <LoginLayout>
                <LoginPage />
              </LoginLayout>
            }
          />

          {/* Admin Pages */}
          <Route
            path="/store-manager/dashboard"
            element={
              <ProtectedRoute>
                <AdminLayout>
                  <AdminDashboardPage />
                </AdminLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/store-manager/edit-Tea/:id"
            element={
              <ProtectedRoute>
                <AdminLayout>
                  <EditTeaPage />
                </AdminLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/store-manager/delete-Tea"
            element={
              <ProtectedRoute>
                <AdminLayout>
                  <DeleteTeaPage />
                </AdminLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/store-manager/products"
            element={
              <ProtectedRoute>
                <AdminLayout>
                  <AdminProductPage />
                </AdminLayout>
              </ProtectedRoute>
            }
          />

          {/* Public Pages */}
          <Route
            path="/"
            element={
              <PublicLayout>
                <Homepage />
              </PublicLayout>
            }
          />
          <Route
            path="/products"
            element={
              <PublicLayout>
                <Productpage />
              </PublicLayout>
            }
          />
          <Route
            path="/products/:id"
            element={
              <PublicLayout>
                <ProductDetailpage />
              </PublicLayout>
            }
          />
          <Route
            path="/about"
            element={
              <PublicLayout>
                <Aboutpage />
              </PublicLayout>
            }
          />
          <Route
            path="/contact"
            element={
              <PublicLayout>
                <ContactPage />
              </PublicLayout>
            }
          />
          <Route
            path="/favorites"
            element={
              <PublicLayout>
                <Favoritepage />
              </PublicLayout>
            }
          />
          <Route
            path="/cart"
            element={
              <PublicLayout>
                <Cartpage />
              </PublicLayout>
            }
          />
          <Route
            path="/profile"
            element={
              <PublicLayout>
                <Profilepage />
              </PublicLayout>
            }
          />

          {/* 404 Not Found */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Router>
    </ShopProvider>
  );
}

export default App;
