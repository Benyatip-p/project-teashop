// src/components/ProtectedRoute.jsx
import React, { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";

const ProtectedRoute = ({ children }) => {
  const [isLoading, setIsLoading] = useState(true);   // สถานะกำลังเช็ค
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");  // หรือใช้ isAdminAuthenticated
    if (token) {
      setIsAuthenticated(true);
    } else {
      setIsAuthenticated(false);
    }
    setIsLoading(false);  // เช็คเสร็จแล้ว
  }, []);

  if (isLoading) {
    // สามารถเปลี่ยนเป็น spinner / skeleton page
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <p className="text-green-700 text-lg">Loading...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children;
};

export default ProtectedRoute;
