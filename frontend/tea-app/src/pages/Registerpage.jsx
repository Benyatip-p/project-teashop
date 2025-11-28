import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import {
  LockClosedIcon,
  UserIcon,
  MailIcon,
  EyeIcon,
  EyeOffIcon,
} from "@heroicons/react/outline";

const RegisterPage = () => {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    firstName: "",
    lastName: "",
    password: "",
    confirmPassword: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    // Validate passwords match
    if (formData.password !== formData.confirmPassword) {
      setError("รหัสผ่านไม่ตรงกัน");
      return;
    }

    // Validate password length
    if (formData.password.length < 8) {
      setError("รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร");
      return;
    }

    setLoading(true);

    try {
      await axios.post("http://localhost:8080/auth/register", {
        username: formData.username,
        email: formData.email,
        password: formData.password,
        first_name: formData.firstName || null,
        last_name: formData.lastName || null,
      });

      // Registration successful, redirect to login
      navigate("/login", { 
        state: { message: "ลงทะเบียนสำเร็จ! กรุณาเข้าสู่ระบบ" } 
      });
    } catch (err) {
      const msg =
        err.response?.data?.message ||
        err.response?.data?.error ||
        "เกิดข้อผิดพลาดในการลงทะเบียน";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center py-12 px-4">
      <div className="w-full max-w-4xl bg-white rounded-3xl shadow-lg border border-gray-100 overflow-hidden grid md:grid-cols-5">
        {/* Left Panel - Branding */}
        <div className="hidden md:flex md:col-span-2 flex-col justify-between bg-viridian-900 text-emerald-50 p-8">
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
              สมัครสมาชิกเพื่อรับสิทธิพิเศษมากมาย 
              ติดตามคำสั่งซื้อ และเก็บรายการโปรดของคุณไว้ในที่เดียว
            </p>
          </div>
          <p className="mt-8 text-[11px] text-emerald-100/70">
            เริ่มต้นการเดินทางสู่โลกแห่งชาคุณภาพกับเรา
          </p>
        </div>

        {/* Right Panel - Form */}
        <div className="md:col-span-3 p-8 md:p-10">
          {/* Mobile Logo */}
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

          {/* Header */}
          <div className="mb-6 md:mb-8">
            <h1 className="text-2xl md:text-3xl font-semibold text-gray-900">
              สมัครสมาชิก
            </h1>
            <p className="mt-2 text-sm text-gray-500">
              สร้างบัญชีใหม่เพื่อเริ่มต้นช้อปปิ้งชาคุณภาพ
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="bg-red-50 border border-red-400 text-red-700 px-4 py-2 rounded-lg text-sm">
                {error}
              </div>
            )}

            {/* Username */}
            <div>
              <label
                htmlFor="username"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                ชื่อผู้ใช้ <span className="text-red-500">*</span>
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
                  value={formData.username}
                  onChange={handleChange}
                  placeholder="กรอกชื่อผู้ใช้"
                  required
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-viridian-500 focus:border-viridian-500 bg-white"
                />
              </div>
            </div>

            {/* Email */}
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                อีเมล <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <MailIcon className="h-5 w-5 text-viridian-800" />
                </div>
                <input
                  type="email"
                  id="email"
                  name="email"
                  autoComplete="email"
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="กรอกอีเมล"
                  required
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-viridian-500 focus:border-viridian-500 bg-white"
                />
              </div>
            </div>

            {/* Name Fields - Two columns */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* First Name */}
              <div>
                <label
                  htmlFor="firstName"
                  className="block text-sm font-medium text-gray-700 mb-1"
                >
                  ชื่อจริง
                </label>
                <input
                  type="text"
                  id="firstName"
                  name="firstName"
                  autoComplete="given-name"
                  value={formData.firstName}
                  onChange={handleChange}
                  placeholder="กรอกชื่อจริง"
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-viridian-500 focus:border-viridian-500 bg-white"
                />
              </div>

              {/* Last Name */}
              <div>
                <label
                  htmlFor="lastName"
                  className="block text-sm font-medium text-gray-700 mb-1"
                >
                  นามสกุล
                </label>
                <input
                  type="text"
                  id="lastName"
                  name="lastName"
                  autoComplete="family-name"
                  value={formData.lastName}
                  onChange={handleChange}
                  placeholder="กรอกนามสกุล"
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-viridian-500 focus:border-viridian-500 bg-white"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                รหัสผ่าน <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <LockClosedIcon className="h-5 w-5 text-viridian-800" />
                </div>
                <input
                  type={showPassword ? "text" : "password"}
                  id="password"
                  name="password"
                  autoComplete="new-password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="กรอกรหัสผ่าน (อย่างน้อย 8 ตัวอักษร)"
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

            {/* Confirm Password */}
            <div>
              <label
                htmlFor="confirmPassword"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                ยืนยันรหัสผ่าน <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <LockClosedIcon className="h-5 w-5 text-viridian-800" />
                </div>
                <input
                  type={showConfirmPassword ? "text" : "password"}
                  id="confirmPassword"
                  name="confirmPassword"
                  autoComplete="new-password"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  placeholder="กรอกรหัสผ่านอีกครั้ง"
                  required
                  className="w-full pl-10 pr-10 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-viridian-500 focus:border-viridian-500 bg-white"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword((prev) => !prev)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                >
                  {showConfirmPassword ? (
                    <EyeOffIcon className="h-5 w-5 text-viridian-800" />
                  ) : (
                    <EyeIcon className="h-5 w-5 text-viridian-800" />
                  )}
                </button>
              </div>
            </div>

            {/* Terms Agreement */}
            <div className="flex items-start gap-2 text-xs md:text-sm text-gray-600">
              <input
                type="checkbox"
                id="terms"
                required
                className="form-checkbox h-4 w-4 text-viridian-700 mt-0.5"
              />
              <label htmlFor="terms">
                ฉันยอมรับ{" "}
                <Link
                  to="/terms"
                  className="text-viridian-800 hover:text-viridian-900 hover:underline"
                >
                  ข้อกำหนดและเงื่อนไข
                </Link>{" "}
                และ{" "}
                <Link
                  to="/privacy"
                  className="text-viridian-800 hover:text-viridian-900 hover:underline"
                >
                  นโยบายความเป็นส่วนตัว
                </Link>
              </label>
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
              {loading ? "กำลังสมัครสมาชิก..." : "สมัครสมาชิก"}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-gray-600">
            <span>มีบัญชีอยู่แล้ว? </span>
            <Link
              to="/login"
              className="text-viridian-800 font-semibold hover:underline"
            >
              เข้าสู่ระบบ
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

export default RegisterPage;