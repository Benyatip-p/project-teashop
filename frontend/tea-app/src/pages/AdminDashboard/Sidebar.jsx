import React from "react";
import { useNavigate } from "react-router-dom";
import {
  MenuAlt2Icon,
  LogoutIcon,
  HomeIcon,
  ChartBarIcon,
  CollectionIcon,
} from "@heroicons/react/outline";

const Sidebar = ({ sidebarOpen, setSidebarOpen, handleLogout }) => {
  const navigate = useNavigate();

  return (
    <aside className={`bg-viridian-700 text-white h-screen transition-all duration-300 ${sidebarOpen ? "w-64" : "w-16"}`}>
  <div className="flex items-center justify-between p-4">
    <div className="flex items-center space-x-3">
      <img src="/images/logo.svg" alt="logo" className={`h-8 ${sidebarOpen ? "block" : "hidden"}`} />
      <span className={`font-bold text-lg ${sidebarOpen ? "block" : "hidden"}`}>GOODTEA</span>
    </div>
    <button
      aria-label="Toggle sidebar"
      onClick={() => setSidebarOpen(!sidebarOpen)}
      className="p-2 rounded-md hover:bg-green-600 transition-colors duration-200"
    >
      <MenuAlt2Icon className="h-5 w-5 text-white" />
    </button>
  </div>

  <nav className="mt-6 px-2 flex flex-col gap-2">
    {[
      { name: "Dashboard", icon: HomeIcon, path: "/" },
      { name: "รายงาน", icon: ChartBarIcon, path: "/reports" },
      { name: "จัดการสินค้า", icon: CollectionIcon, path: "/store-manager/products" },
    ].map((item, idx) => (
      <button
        key={idx}
        onClick={() => navigate(item.path)}
        className={`group flex items-center p-2 rounded-md hover:bg-green-600 transition-all duration-200 ${sidebarOpen ? "justify-start" : "justify-center"}`}
      >
        <item.icon className="h-5 w-5 text-white" />
        <span className={`ml-3 ${sidebarOpen ? "inline" : "hidden"}`}>{item.name}</span>

        {!sidebarOpen && (
          <span className="absolute left-full ml-2 bg-black text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100">
            {item.name}
          </span>
        )}
      </button>
    ))}

    <div className="mt-6 border-t border-green-600 pt-4">
      <button
        onClick={handleLogout}
        className={`flex items-center w-full p-2 rounded-md hover:bg-red-600 transition-all duration-200 text-white`}
      >
        <LogoutIcon className="h-5 w-5" />
        <span className={`ml-3 ${sidebarOpen ? "inline" : "hidden"}`}>ออกจากระบบ</span>
      </button>
    </div>
  </nav>
</aside>
  );
};

export default Sidebar;
