// src/pages/Profilepage.jsx
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";

const Profilepage = () => {
  const navigate = useNavigate();
  const [userInfo, setUserInfo] = useState({
    username: "",
    role: "",
  });

  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (!token) {
      navigate("/login", { replace: true });
      return;
    }

    try {
      const decoded = jwtDecode(token);
      const roles = Array.isArray(decoded.roles) ? decoded.roles : [];
      setUserInfo({
        username: decoded.username || "",
        role: roles[0] || "user",
      });
    } catch {
      localStorage.removeItem("access_token");
      navigate("/login", { replace: true });
    }
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    navigate("/login", { replace: true });
  };

  return (
    <div className="min-h-[calc(100vh-72px)] bg-gray-50">
      <div className="container mx-auto px-4 py-10">
        <div className="mx-auto max-w-xl rounded-2xl bg-white p-8 shadow-sm">
          <h1 className="mb-6 text-2xl font-semibold text-gray-900">
            โปรไฟล์ของฉัน
          </h1>

          <div className="mb-6 space-y-2 text-sm text-gray-700">
            {userInfo.username && (
              <div className="flex justify-between">
                <span className="text-gray-500">ชื่อผู้ใช้</span>
                <span className="font-medium">{userInfo.username}</span>
              </div>
            )}
            {userInfo.role && (
              <div className="flex justify-between">
                <span className="text-gray-500">สิทธิ์การใช้งาน</span>
                <span className="rounded-full bg-emerald-50 px-3 py-0.5 text-xs font-semibold text-emerald-700">
                  {userInfo.role === "admin" ? "ผู้ดูแลระบบ" : "ผู้ใช้งานทั่วไป"}
                </span>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={handleLogout}
            className="mt-4 w-full rounded-xl bg-red-500 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-red-600"
          >
            ออกจากระบบ
          </button>
        </div>
      </div>
    </div>
  );
};

export default Profilepage;
