import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

import Navbar from "./components/Navbar";
import Footer from "./components/Footer";
import NotFound from "./components/Notfound";
import { ShopProvider } from "./context/ShopContext";
import ProtectedRoute from "./components/ProtectedRoute";

import Homepage from "./pages/Homepage";
import ContactPage from "./pages/Contactpage";
import Aboutpage from "./pages/Aboutpage";
import Productpage from "./pages/Productpage";
import Favoritepage from "./pages/Favoritepage";
import Cartpage from "./pages/Cartpage";
import Profilepage from "./pages/Profilepage";
import ProductDetailpage from "./pages/ProductDetailpage";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/Registerpage";
import DeleteTeaPage from "./pages/DeleteTeaPage";
import EditTeaPage from "./pages/EditTeaPage/EditTeaPage";
import AdminDashboardPage from "./pages/AdminDashboard/AdminDashboard";
import AdminProductPage from "./pages/AdminDashboard/AdminProductPage";
import Paymentpage from "./pages/Paymentpage";
import CategoryProductspage from "./pages/CategoryProductspage";

const PublicLayout = ({ children }) => (
  <div className="flex flex-col min-h-screen bg-gray-50">
    <Navbar />
    <main className="flex-grow">{children}</main>
    <Footer />
  </div>
);

const AuthLayout = ({ children }) => (
  <div className="min-h-screen bg-gray-50 flex items-center justify-center">
    {children}
  </div>
);

const AdminLayout = ({ children }) => <>{children}</>;

function App() {
  return (
    <ShopProvider>
      <Router>
        <Routes>
          <Route
            path="/login"
            element={
              <PublicLayout>
                <LoginPage />
              </PublicLayout>
            }
          />

          <Route
            path="/register"
            element={
              <PublicLayout>
                <RegisterPage />
              </PublicLayout>
            }
          />

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
            path="/user/account/profile"
            element={
              <PublicLayout>
                <Profilepage />
              </PublicLayout>
            }
          />
          <Route
            path="/payment"
            element={
              <PublicLayout>
                <Paymentpage />
              </PublicLayout>
            }
          />
          <Route
            path="/category/:categoryName"
            element={
              <PublicLayout>
                <CategoryProductspage />
              </PublicLayout>
            }
          />

          <Route path="*" element={<NotFound />} />
        </Routes>
      </Router>
    </ShopProvider>
  );
}

export default App;
