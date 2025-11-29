import React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { jwtDecode } from "jwt-decode";

const getDecodedToken = () => {
  // Check both localStorage and sessionStorage for token
  const token = localStorage.getItem("access_token") || sessionStorage.getItem("access_token");
  if (!token) return null;

  try {
    const decoded = jwtDecode(token);

    if (decoded.exp && decoded.exp < Date.now() / 1000) {
      // Clear from both storages if token is expired
      localStorage.removeItem("access_token");
      sessionStorage.removeItem("access_token");
      return null;
    }

    return decoded;
  } catch {
    // Clear from both storages if token is invalid
    localStorage.removeItem("access_token");
    sessionStorage.removeItem("access_token");
    return null;
  }
};

const ProtectedRoute = ({ children, allowedRoles = [] }) => {
  const location = useLocation();
  const decoded = getDecodedToken();

  if (!decoded) {
    return (
      <Navigate
        to="/login"
        replace
        state={{ redirectTo: location.pathname }}
      />
    );
  }

  const roles = Array.isArray(decoded.roles) ? decoded.roles : [];
  const hasRequiredRole =
    allowedRoles.length === 0 ||
    roles.some(role => allowedRoles.includes(role));

  if (!hasRequiredRole) {
    return <Navigate to="/not-authorized" replace />;
  }

  return children;
};

export default ProtectedRoute;
