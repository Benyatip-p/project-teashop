import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { BookOpenIcon, PlusIcon, PencilAltIcon, TrashIcon, LogoutIcon } from "@heroicons/react/outline";

const AdminDashboardPage = () => {
  const navigate = useNavigate();

  useEffect(() => {
    if (localStorage.getItem("isAdminAuthenticated") !== "true") {
      navigate("/login");
    }
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem("isAdminAuthenticated");
    localStorage.removeItem("adminUser");
    navigate("/login");
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-gradient-to-r from-viridian-600 to-green-700 text-white shadow-lg">
        <div className="container mx-auto px-4 py-6 flex justify-between items-center">
          <div className="flex items-center space-x-3">
            <BookOpenIcon className="h-8 w-8 text-black" />
            <h1 className="text-black font-semibold">GOODTEA - Admin Dashboard</h1>
          </div>

          {/* Logout Button */}
          <button
            onClick={handleLogout}
            className="flex items-center space-x-2 px-4 py-2 bg-black hover:bg-gray-800 rounded-lg"
          >
            <LogoutIcon className="h-5 w-5 text-white" />
            <span className="text-white font-semibold">ออกจากระบบ</span>
          </button>
        </div>
      </header>

      {/* Main Dashboard */}
      <div className="container mx-auto px-4 py-8">
        <h2 className="text-3xl font-bold mb-6">สวัสดี Admin! เลือกเมนูที่ต้องการ</h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div
            onClick={() => navigate("/store-manager/add-Tea")}
            className="cursor-pointer bg-white p-6 rounded-xl shadow hover:shadow-lg transition flex flex-col items-center justify-center"
          >
            <PlusIcon className="h-12 w-12 text-green-600 mb-2" />
            <h3 className="text-xl font-semibold mb-1">เพิ่ม Products</h3>
            <p className="text-gray-500 text-center">เพิ่ม Products เข้าสู่ระบบร้าน</p>
          </div>

          <div
            onClick={() => navigate("/store-manager/edit-Tea/:id")}
            className="cursor-pointer bg-white p-6 rounded-xl shadow hover:shadow-lg transition flex flex-col items-center justify-center"
          >
            <PencilAltIcon className="h-12 w-12 text-yellow-600 mb-2" />
            <h3 className="text-xl font-semibold mb-1">แก้ไข Products</h3>
            <p className="text-gray-500 text-center">แก้ไขรายละเอียดProductsที่มีอยู่</p>
          </div>

          <div
            onClick={() => navigate("/store-manager/delete-Tea")}
            className="cursor-pointer bg-white p-6 rounded-xl shadow hover:shadow-lg transition flex flex-col items-center justify-center"
          >
            <TrashIcon className="h-12 w-12 text-red-600 mb-2" />
            <h3 className="text-xl font-semibold mb-1">ลบ Products</h3>
            <p className="text-gray-500 text-center">ลบ Products ออกจากระบบ</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboardPage;
