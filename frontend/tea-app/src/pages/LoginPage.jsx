// src/pages/LoginPage.jsx
import React, { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { LockClosedIcon, UserIcon, EyeIcon, EyeOffIcon } from "@heroicons/react/outline";

const LoginPage = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      navigate("/store-manager/dashboard");
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch("http://localhost:8080/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();

      if (res.ok) {
        localStorage.setItem("token", data.access_token);
        localStorage.setItem("adminUser", JSON.stringify(data.user));
        navigate("/store-manager/dashboard");
      } else {
        setError(data.error || "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง");
      }
    } catch (err) {
      console.error(err);
      setError("เกิดข้อผิดพลาดในการเชื่อมต่อเซิร์ฟเวอร์");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-r from-viridian-700 to-green-700 text-black p-4 shadow-md">
      <div className="container mx-auto max-w-md px-4">
        <div className="bg-white rounded-2xl shadow-lg p-8">
          {/* Logo */}
          <div className="text-center mb-6">
            <Link to="/">
              <img src="/images/logo.svg" alt="Logo" className="mx-auto h-16 w-16" />
            </Link>
            <p className="mt-2 text-green-800 font-semibold">เข้าสู่ระบบ BackOffice</p>
            <p className="text-green-600 text-sm">สำหรับผู้ดูแลระบบเท่านั้น</p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="bg-red-50 border border-red-400 text-red-700 px-4 py-2 rounded-lg text-sm">
                {error}
              </div>
            )}

            {/* Username */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-green-700 mb-1">
                Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <UserIcon className="h-5 w-5 text-green-700" />
                </div>
                <input
                  type="text"
                  id="username"
                  name="username"               // เพิ่ม name
                  autoComplete="username"       // เพิ่ม autocomplete
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="กรอกชื่อผู้ใช้"
                  required
                  className="w-full pl-10 pr-4 py-3 border border-green-700 rounded-xl focus:outline-none focus:ring-2 focus:ring-green-400 focus:border-green-400"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-green-700 mb-1">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <LockClosedIcon className="h-5 w-5 text-green-700" />
                </div>
                <input
                  type={showPassword ? "text" : "password"}
                  id="password"
                  name="password"                  // เพิ่ม name
                  autoComplete="current-password"  // เพิ่ม autocomplete
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="กรอกรหัสผ่าน"
                  required
                  className="w-full pl-10 pr-10 py-3 border border-green-700 rounded-xl focus:outline-none focus:ring-2 focus:ring-green-400 focus:border-green-400"
                />
                <div
                  className="absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOffIcon className="h-5 w-5 text-green-700" />
                  ) : (
                    <EyeIcon className="h-5 w-5 text-green-700" />
                  )}
                </div>
              </div>
            </div>

            {/* Remember + Forgot */}
            <div className="flex items-center justify-between text-sm text-green-700">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked readOnly className="form-checkbox h-4 w-4 text-green-600" />
                Remember this Device
              </label>
              <Link to="/" className="text-green-600 hover:underline">
                Forgot Password?
              </Link>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className={`w-full py-3 text-white font-semibold rounded-xl transition-colors ${
                loading ? "bg-green-400 cursor-not-allowed" : "bg-green-700 hover:bg-green-800"
              }`}
            >
              {loading ? "Loading..." : "Sign In"}
            </button>
          </form>

          {/* Register */}
          <div className="mt-6 text-center text-green-800 text-sm">
            <span>New Admin? </span>
            <Link to="/register" className="text-green-700 font-semibold hover:underline">
              Create an account
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
