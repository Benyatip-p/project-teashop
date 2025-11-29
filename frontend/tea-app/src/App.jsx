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

import SidebarProfile from "./components/SidebarProfile";
import Profilepage from "./pages/Profilepage";
import Addresspage from "./pages/Addresspage";

import ProductDetailpage from "./pages/ProductDetailpage";

import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/Registerpage";
import Paymentpage from "./pages/Paymentpage";

import DeleteTeaPage from "./pages/DeleteTeaPage";
import EditTeaPage from "./pages/EditTeaPage/EditTeaPage";
import AdminDashboardPage from "./pages/AdminDashboard/AdminDashboard";
import AdminOrderpage from "./pages/AdminOrderpage";
import AdminProductPage from "./pages/AdminDashboard/AdminProductPage";
import CategoryProductspage from "./pages/CategoryProductspage";
import Purchasepage from "./pages/Purchasepage";
import ResetPasswordPage from "./pages/ResetPasswordPage";

import CreateTeaPage from "./pages/EditTeaPage/CreateTeaPage";


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

const AccountLayout = ({ children }) => (
  <PublicLayout>
    <div className="container mx-auto px-4 py-8 flex flex-col md:flex-row gap-6">
      <SidebarProfile />
      <div className="flex-1 w-full min-w-0">{children}</div>
    </div>
  </PublicLayout>
);


function App() {
  return (
    <ShopProvider>
      <Router>
        <Routes>

          {/* Auth Routes */}
          <Route path="/login" element={<AuthLayout><LoginPage /></AuthLayout>} />
          <Route path="/register" element={<AuthLayout><RegisterPage /></AuthLayout>} />
          <Route path="/reset-password" element={<AuthLayout><ResetPasswordPage /></AuthLayout>} />
          <Route path="/not-authorized" element={<AuthLayout><NotAuthorized /></AuthLayout>} />

          {/* ADMIN ROUTES */}
          <Route
            path="/admin/dashboard"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <AdminDashboardPage />
              </ProtectedRoute>
            }
          />

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

          <Route
            path="/admin/orders"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <AdminOrderpage />
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
            path="/payment"
            element={
              <ProtectedRoute>
                <PublicLayout>
                  <Paymentpage />
                </PublicLayout>
              </ProtectedRoute>
            }
          />

          <Route
            path="/user/account/profile"
            element={
              <ProtectedRoute>
                <AccountLayout>
                  <Profilepage />
                </AccountLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/user/account/address"
            element={
              <ProtectedRoute>
                <AccountLayout>
                  <Addresspage />
                </AccountLayout>
              </ProtectedRoute>
            }
          />

          <Route
            path="/user/purchase"
            element={
              <ProtectedRoute>
                <AccountLayout>
                  <Purchasepage />
                </AccountLayout>
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
