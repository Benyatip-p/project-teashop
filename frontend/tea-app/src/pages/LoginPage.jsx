import React, { useState, useEffect, useCallback } from "react";
import { useNavigate, Link, useLocation } from "react-router-dom";
import axios from "axios";
import {
  LockClosedIcon,
  UserIcon,
  EyeIcon,
  EyeOffIcon,
} from "@heroicons/react/outline";
import { jwtDecode } from "jwt-decode";

// Map role names to role_id
const ROLE_ID_MAP = {
  admin: 1,
  user: 2,
};

const getRoleIdFromToken = (token) => {
  if (!token) return null;

  try {
    const decoded = jwtDecode(token);

    if (decoded.exp && decoded.exp < Date.now() / 1000) {
      return null;
    }

    const roles = Array.isArray(decoded.roles) ? decoded.roles : [];
    const roleName = roles[0] || "user";
    return ROLE_ID_MAP[roleName] || 2; // Default to user (role_id = 2)
  } catch {
    return null;
  }
};

const LoginPage = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();
  const location = useLocation();

  // Get the previous page from location state, or use referrer
  const from = location.state?.from?.pathname || location.state?.redirectTo || null;
  const redirectState = location.state?.checkoutData || null;

  const redirectByRoleId = useCallback(
    (roleId) => {
      if (roleId === 1) {
        // Store manager (admin) - always redirect to store manager dashboard
        navigate("/store-manager/dashboard", { replace: true });
      } else if (roleId === 2) {
        // Regular user - redirect to previous page or home
        if (from) {
          navigate(from, { replace: true, state: redirectState });
        } else {
          navigate("/", { replace: true });
        }
      } else {
        // Fallback to home
        navigate("/", { replace: true });
      }
    },
    [navigate, from, redirectState]
  );

  useEffect(() => {
    // Check both localStorage and sessionStorage for existing token
    const token = localStorage.getItem("access_token") || sessionStorage.getItem("access_token");
    if (!token) return;

    const roleId = getRoleIdFromToken(token);
    if (!roleId) {
      // Clear from both storages if token is invalid
      localStorage.removeItem("access_token");
      sessionStorage.removeItem("access_token");
      return;
    }

    redirectByRoleId(roleId);
  }, [redirectByRoleId]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await axios.post("http://localhost:8080/auth/login", {
        username,
        password,
      });

      const token = res.data.access_token;
      
      // Store token based on "Remember Me" preference
      if (rememberMe) {
        localStorage.setItem("access_token", token);
        // Clear sessionStorage if it exists from a previous session
        sessionStorage.removeItem("access_token");
      } else {
        sessionStorage.setItem("access_token", token);
        // Clear localStorage if it exists from a previous session
        localStorage.removeItem("access_token");
      }

      const roleId = getRoleIdFromToken(token);
      if (!roleId) {
        // Clear from both storages if token is invalid
        localStorage.removeItem("access_token");
        sessionStorage.removeItem("access_token");
        setError("ไม่สามารถยืนยันตัวตนได้ กรุณาลองใหม่อีกครั้ง");
        return;
      }

      redirectByRoleId(roleId);
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
      <div className="grid w-full max-w-3xl overflow-hidden rounded-3xl border border-gray-100 bg-white shadow-lg md:grid-cols-2">
        <div className="hidden flex-col justify-between bg-viridian-900 p-8 text-emerald-50 md:flex">
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
            <p className="mt-6 text-sm leading-relaxed text-emerald-100/90">
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
            <h1 className="text-2xl font-semibold text-gray-900 md:text-3xl">
              เข้าสู่ระบบ
            </h1>
            <p className="mt-2 text-sm text-gray-500">
              ล็อกอินด้วยบัญชีของคุณเพื่อดำเนินการสั่งซื้อ
              และจัดการข้อมูลส่วนตัวได้อย่างสะดวก
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="rounded-lg border border-red-400 bg-red-50 px-4 py-2 text-sm text-red-700">
                {error}
              </div>
            )}

            <div>
              <label
                htmlFor="username"
                className="mb-1 block text-sm font-medium text-gray-700"
              >
                ชื่อผู้ใช้
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                  <UserIcon className="h-5 w-5 text-viridian-800" />
                </div>
                <input
                  id="username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="กรอกชื่อผู้ใช้ของคุณ"
                  required
                  className="w-full rounded-xl border border-gray-300 bg-white py-3 pl-10 pr-4 text-sm focus:border-viridian-500 focus:outline-none focus:ring-2 focus:ring-viridian-500"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="password"
                className="mb-1 block text-sm font-medium text-gray-700"
              >
                รหัสผ่าน
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                  <LockClosedIcon className="h-5 w-5 text-viridian-800" />
                </div>
                <input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="กรอกรหัสผ่าน"
                  required
                  className="w-full rounded-xl border border-gray-300 bg-white py-3 pl-10 pr-10 text-sm focus:border-viridian-500 focus:outline-none focus:ring-2 focus:ring-viridian-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute inset-y-0 right-0 flex items-center pr-3"
                >
                  {showPassword ? (
                    <EyeOffIcon className="h-5 w-5 text-viridian-800" />
                  ) : (
                    <EyeIcon className="h-5 w-5 text-viridian-800" />
                  )}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs text-gray-600 md:text-sm">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="h-4 w-4 text-viridian-700 cursor-pointer"
                />
                <span>จดจำการเข้าสู่ระบบบนอุปกรณ์นี้</span>
              </label>
              <Link
                to="/forgot-password"
                className="text-viridian-800 hover:text-viridian-900 hover:underline"
              >
                ลืมรหัสผ่าน?
              </Link>
            </div>

            <button
              type="submit"
              disabled={loading}
              className={`w-full rounded-xl py-3 text-sm font-semibold text-white transition-colors md:text-base ${
                loading
                  ? "cursor-not-allowed bg-viridian-300"
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
              className="font-semibold text-viridian-800 hover:underline"
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
