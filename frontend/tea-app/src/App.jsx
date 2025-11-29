import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

import Navbar from "./components/Navbar";
import Footer from "./components/Footer";
import NotFound from "./components/Notfound";
import NotAuthorized from "./components/NotAuthorized";
import ProtectedRoute from "./components/ProtectedRoute";

import { ShopProvider } from "./context/ShopContext";

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

import CreateTeaPage from "./pages/EditTeaPage/CreateTeaPage"; 

// ===================== LAYOUT =====================
const PublicLayout = ({ children }) => (
  <div className="flex min-h-screen flex-col bg-gray-50">
    <Navbar />
    <main className="flex-grow">{children}</main>
    <Footer />
  </div>
);

const AuthLayout = ({ children }) => (
  <div className="flex min-h-screen items-center justify-center bg-gray-50">
    {children}
  </div>
);

// ===================== ROUTING =====================
function App() {
  return (
    <ShopProvider>
      <Router>
        <Routes>

          {/* Auth Routes */}
          <Route path="/login" element={<AuthLayout><LoginPage /></AuthLayout>} />
          <Route path="/register" element={<AuthLayout><RegisterPage /></AuthLayout>} />
          <Route path="/not-authorized" element={<AuthLayout><NotAuthorized /></AuthLayout>} />

          {/* ADMIN ONLY ROUTES */}
          <Route
            path="/admin/dashboard"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <AdminDashboardPage />
              </ProtectedRoute>
            }
          />

          {/* ⭐⭐ เพิ่มเส้นนี้แล้วใช้งานได้เลย ⭐⭐ */}
          <Route
            path="/admin/create-products"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <CreateTeaPage />
              </ProtectedRoute>
            }
          />

          <Route
            path="/admin/update-products/:id"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <EditTeaPage />
              </ProtectedRoute>
            }
          />

          <Route
            path="/admin/delete-tea"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <DeleteTeaPage />
              </ProtectedRoute>
            }
          />

          <Route
            path="/admin/products"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <AdminProductPage />
              </ProtectedRoute>
            }
          />

          {/* PUBLIC */}
          <Route path="/" element={<PublicLayout><Homepage /></PublicLayout>} />
          <Route path="/products" element={<PublicLayout><Productpage /></PublicLayout>} />
          <Route path="/products/:id" element={<PublicLayout><ProductDetailpage /></PublicLayout>} />
          <Route path="/about" element={<PublicLayout><Aboutpage /></PublicLayout>} />
          <Route path="/contact" element={<PublicLayout><ContactPage /></PublicLayout>} />
          <Route path="/favorites" element={<PublicLayout><Favoritepage /></PublicLayout>} />
          <Route path="/cart" element={<PublicLayout><Cartpage /></PublicLayout>} />

          {/* USER PROFILE */}
          <Route
            path="/user/account/profile"
            element={
              <ProtectedRoute>
                <PublicLayout>
                  <Profilepage />
                </PublicLayout>
              </ProtectedRoute>
            }
          />

          {/* PAYMENT */}
          <Route
            path="/payment"
            element={
              <ProtectedRoute>
                <PublicLayout>
                  <Paymentpage />
                </PublicLayout>
              </ProtectedRoute>
            }
          />

          {/* CATEGORY PAGE */}
          <Route
            path="/category/:categoryName"
            element={<PublicLayout><CategoryProductspage /></PublicLayout>}
          />

          {/* 404 */}
          <Route path="*" element={<NotFound />} />

        </Routes>
      </Router>
    </ShopProvider>
  );
}

export default App;
