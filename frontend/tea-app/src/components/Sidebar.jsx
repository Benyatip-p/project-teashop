import React from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  MenuAlt2Icon,
  LogoutIcon,
  HomeIcon,
  CollectionIcon,
} from "@heroicons/react/outline";

const Sidebar = ({ sidebarOpen, setSidebarOpen, handleLogout }) => {
  const navigate = useNavigate();
  const location = useLocation();

  const navItems = [
    { name: "Dashboard", icon: HomeIcon, path: "/admin/dashboard" },
    { name: "จัดการสินค้า", icon: CollectionIcon, path: "/admin/products" },
  ];

  const isActive = (path) => location.pathname.startsWith(path);

  return (
    <aside
      // แก้ไขตรงนี้: เพิ่ม sticky top-0 เพื่อให้เกาะติดขอบบนตลอดเวลา
      className={`sticky top-0 h-screen bg-viridian-800 text-white flex flex-col transition-all duration-300 shadow-xl ${
        sidebarOpen ? "w-64" : "w-20"
      }`}
    >
      <div className="flex items-center justify-between px-4 py-4 border-b border-viridian-700">
        <div className="flex items-center space-x-3">
          <img
            src="/images/logo.svg"
            alt="GOODTEA"
            className="h-9 w-9 rounded-full bg-emerald-100 p-1"
          />
          {sidebarOpen && (
            <div>
              <p className="font-semibold text-lg tracking-wide">GOODTEA</p>
              <p className="text-xs text-emerald-100/70">แผงควบคุมร้านค้า</p>
            </div>
          )}
        </div>

        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="h-9 w-9 flex items-center justify-center rounded-md hover:bg-viridian-700"
        >
          <MenuAlt2Icon className="h-5 w-5 text-white" />
        </button>
      </div>

      <nav className="flex-1 px-2 py-6 space-y-2">
        {navItems.map((item) => {
          const active = isActive(item.path);
          const Icon = item.icon;

          return (
            <button
              key={item.name}
              onClick={() => navigate(item.path)}
              className={`group relative flex items-center rounded-lg transition-all duration-200 px-3 py-3 w-full ${
                sidebarOpen ? "justify-start" : "justify-center"
              }`}
            >
              <div
                className={`absolute left-0 top-0 h-full w-1 rounded-r-full transition-all duration-300 ${
                  active ? "bg-emerald-400" : "bg-transparent group-hover:bg-emerald-300/40"
                }`}
              />

              <Icon
                className={`h-6 w-6 transition-colors ${
                  active ? "text-emerald-300" : "text-emerald-100 group-hover:text-white"
                }`}
              />

              {sidebarOpen && (
                <span
                  className={`ml-3 text-sm font-medium transition-colors ${
                    active ? "text-white" : "text-emerald-100 group-hover:text-white"
                  }`}
                >
                  {item.name}
                </span>
              )}

              {!sidebarOpen && (
                <span className="absolute left-full ml-3 rounded-md bg-slate-900 px-2 py-1 text-xs text-white opacity-0 shadow-lg transition-opacity group-hover:opacity-100 whitespace-nowrap z-50">
                  {item.name}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="border-t border-viridian-700 px-2 py-4">
        <button
          onClick={handleLogout}
          className={`group relative flex items-center px-3 py-3 rounded-lg text-rose-100 hover:bg-rose-600/20 w-full ${
            sidebarOpen ? "justify-start" : "justify-center"
          }`}
        >
          <LogoutIcon className="h-6 w-6" />
          {sidebarOpen && (
            <span className="ml-3 text-sm font-medium">ออกจากระบบ</span>
          )}
          {!sidebarOpen && (
            <span className="absolute left-full ml-3 rounded-md bg-slate-900 px-2 py-1 text-xs text-white opacity-0 shadow-lg transition-opacity group-hover:opacity-100 whitespace-nowrap z-50">
              ออกจากระบบ
            </span>
          )}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;