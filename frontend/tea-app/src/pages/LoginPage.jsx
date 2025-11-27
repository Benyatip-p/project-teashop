import React, { useState } from "react";
import { useNavigate, Link, useLocation } from "react-router-dom";
import axios from "axios";
import {
  LockClosedIcon,
  UserIcon,
  EyeIcon,
  EyeOffIcon,
} from "@heroicons/react/outline";

const LoginPage = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const token = localStorage.getItem("access_token");
    const user = JSON.parse(localStorage.getItem("user") || "{}");

    if (token && user.roles) {
      // Redirect based on user role
      if (user.roles.includes("admin")) {
        navigate("/admin/dashboard", { replace: true });
      } else {
        navigate("/", { replace: true });
      }
    }
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await axios.post("http://localhost:8080/auth/login", {
        username,
        password,
      });

      // Save token and user data
      localStorage.setItem("access_token", res.data.access_token);
      localStorage.setItem("user", JSON.stringify(res.data.user));

      // Check user roles and redirect accordingly
      const userRoles = res.data.user.roles || [];

      if (userRoles.includes("admin")) {
        navigate("/admin/dashboard", { replace: true });
      } else {
        // For "user" role or any other roles, redirect to homepage
        navigate("/", { replace: true });
      }
    } catch (err) {
      const msg =
        err.response?.data?.message ||
        err.response?.data?.error ||
        "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center py-12 px-4">
      <div className="w-full max-w-3xl bg-white rounded-3xl shadow-lg border border-gray-100 overflow-hidden grid md:grid-cols-2">
        <div className="hidden md:flex flex-col justify-between bg-viridian-900 text-emerald-50 p-8">
          <div>
            <Link to="/" className="inline-flex items-center gap-3">
              <img
                src="/images/logo.svg"
                alt="GOODTEA"
                className="h-9 w-9 rounded-full bg-emerald-50 p-1"
              />
              <span className="text-lg font-semibold tracking-wide">
                GOODTEA
              </span>
            </Link>
            <p className="mt-6 text-sm text-emerald-100/90 leading-relaxed">
              เข้าสู่ระบบเพื่อจัดการคำสั่งซื้อของคุณ ดูประวัติการสั่งซื้อ
              และเก็บรายการโปรดของคุณไว้ในที่เดียว
            </p>
          </div>
          <p className="mt-8 text-[11px] text-emerald-100/70">
            ช่วงเวลาจิบชาที่ดี เริ่มจากการเลือกถ้วยโปรดของคุณ
          </p>
        </div>

        <div className="p-8 md:p-10">
          <div className="mb-6 md:mb-8 md:hidden">
            <Link to="/" className="flex items-center gap-3">
              <img
                src="/images/logo.svg"
                alt="GOODTEA"
                className="h-9 w-9 rounded-full bg-viridian-900/5 p-1"
              />
              <span className="text-lg font-semibold text-viridian-900">
                GOODTEA
              </span>
            </Link>
          </div>

          <div className="mb-6 md:mb-8">
            <h1 className="text-2xl md:text-3xl font-semibold text-gray-900">
              เข้าสู่ระบบ
            </h1>
            <p className="mt-2 text-sm text-gray-500">
              ล็อกอินด้วยบัญชีของคุณเพื่อดำเนินการสั่งซื้อ
              และจัดการข้อมูลส่วนตัวได้อย่างสะดวก
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="bg-red-50 border border-red-400 text-red-700 px-4 py-2 rounded-lg text-sm">
                {error}
              </div>
            )}

            <div>
              <label
                htmlFor="username"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                ชื่อผู้ใช้
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <UserIcon className="h-5 w-5 text-viridian-800" />
                </div>
                <input
                  type="text"
                  id="username"
                  name="username"
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="กรอกชื่อผู้ใช้ของคุณ"
                  required
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-viridian-500 focus:border-viridian-500 bg-white"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                รหัสผ่าน
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <LockClosedIcon className="h-5 w-5 text-viridian-800" />
                </div>
                <input
                  type={showPassword ? "text" : "password"}
                  id="password"
                  name="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="กรอกรหัสผ่าน"
                  required
                  className="w-full pl-10 pr-10 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-viridian-500 focus:border-viridian-500 bg-white"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                >
                  {showPassword ? (
                    <EyeOffIcon className="h-5 w-5 text-viridian-800" />
                  ) : (
                    <EyeIcon className="h-5 w-5 text-viridian-800" />
                  )}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs md:text-sm text-gray-600">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked
                  readOnly
                  className="form-checkbox h-4 w-4 text-viridian-700"
                />
                <span>จดจำการเข้าสู่ระบบบนอุปกรณ์นี้</span>
              </label>
              <Link
                to="/"
                className="text-viridian-800 hover:text-viridian-900 hover:underline"
              >
                ลืมรหัสผ่าน?
              </Link>
            </div>

            <button
              type="submit"
              disabled={loading}
              className={`w-full py-3 text-white font-semibold rounded-xl text-sm md:text-base transition-colors ${
                loading
                  ? "bg-viridian-300 cursor-not-allowed"
                  : "bg-viridian-900 hover:bg-viridian-800"
              }`}
            >
              {loading ? "กำลังเข้าสู่ระบบ..." : "เข้าสู่ระบบ"}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-gray-600">
            <span>ยังไม่มีบัญชี? </span>
            <Link
              to="/register"
              className="text-viridian-800 font-semibold hover:underline"
            >
              สมัครสมาชิกใหม่
            </Link>
          </div>

          <div className="mt-4 text-center">
            <Link
              to="/"
              className="text-xs text-gray-400 hover:text-gray-600 hover:underline"
            >
              ← กลับไปหน้าแรก
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
