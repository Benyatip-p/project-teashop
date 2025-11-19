import React, { useState } from "react";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";
import DashboardContent from "./DashboardContent";
import { ChartBarIcon, CollectionIcon, UserCircleIcon } from "@heroicons/react/outline";

export default function AdminDashboard() {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("adminUser");
    window.location.href = "/login";  // ป้องกันปัญหา navigate delay
  };

  const stats = [
    { title: "ยอดขายวันนี้", value: "฿12,450", icon: <ChartBarIcon className="h-6 w-6 text-green-600" /> },
    { title: "จำนวนสต็อก", value: "1,234", icon: <CollectionIcon className="h-6 w-6 text-indigo-600" /> },
    { title: "ผู้ใช้งานใหม่", value: "86", icon: <UserCircleIcon className="h-6 w-6 text-yellow-600" /> },
  ];

  const products = [
    { img: "/assets/images/products/s1.jpg", name: "ชาเขียวโฮจิฉะ", price: 120 },
    { img: "/assets/images/products/s2.jpg", name: "ชาไทยพรีเมียม", price: 95 },
    { img: "/assets/images/products/s3.jpg", name: "โอวัลตินเย็น", price: 80 },
    { img: "/assets/images/products/s4.jpg", name: "มัทฉะแฟรป", price: 140 },
  ];

  return (
    <div className="min-h-screen bg-gray-50 flex">
      <Sidebar
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
        handleLogout={handleLogout}
      />
      <div className="flex-1">
        <Topbar />
        <DashboardContent stats={stats} products={products} />
      </div>
    </div>
  );
}
