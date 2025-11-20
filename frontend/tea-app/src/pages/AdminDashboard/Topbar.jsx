import React from "react";
import { SearchIcon, BellIcon } from "@heroicons/react/outline";

const Topbar = () => (
  <header className="flex items-center justify-between bg-gradient-to-r from-viridian-700 to-green-700 text-white p-4 shadow-md">
  <div className="flex items-center space-x-3">
    <h1 className="text-xl font-semibold">GOODTEA - Admin Dashboard</h1>
    <div className="hidden md:block">
      <p className="text-sm opacity-90">สวัสดี Admin — จัดการข้อมูลร้านของคุณได้ที่นี่</p>
    </div>
  </div>

  <div className="flex items-center space-x-3">
    <div className="relative hidden sm:block">
      <input
        placeholder="ค้นหา..."
        className="rounded-md py-1 px-3 text-sm text-gray-800 bg-white focus:outline-none focus:ring-2 focus:ring-viridian-500 shadow-sm"
      />
      <SearchIcon className="h-4 w-4 absolute right-2 top-2 text-gray-500" />
    </div>
    <button className="p-2 rounded-full hover:bg-white/10 transition transform hover:scale-110">
      <BellIcon className="h-5 w-5" />
    </button>
    <div className="flex items-center space-x-2">
      <img
        src="/images/logo.svg"
        alt="avatar"
        className="h-8 w-8 rounded-full bg-white p-1 ring-2 ring-white shadow-sm"
      />
      <span className="text-sm font-medium">Admin</span>
    </div>
  </div>
</header>
);

export default Topbar;
