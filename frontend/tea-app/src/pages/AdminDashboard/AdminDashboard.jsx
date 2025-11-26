import React, { useState } from "react";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";
import DashboardContent from "./DashboardContent";
import {
  ChartBarIcon,
  CollectionIcon,
  UserCircleIcon,
} from "@heroicons/react/outline";

export default function AdminDashboard() {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("adminUser");
    sessionStorage.removeItem("access_token");
    window.location.href = "/login";
  };

  const stats = [
    {
      id: "today-sales",
      title: "ยอดขายวันนี้",
      value: "฿12,450",
      trendLabel: "เทียบกับเมื่อวาน",
      trendValue: "+18.3%",
      iconBg: "bg-emerald-50",
      icon: <ChartBarIcon className="h-6 w-6 text-emerald-600" />,
    },
    {
      id: "stock",
      title: "จำนวนสต็อก",
      value: "1,234",
      trendLabel: "สินค้าใกล้หมด",
      trendValue: "8 รายการ",
      iconBg: "bg-sky-50",
      icon: <CollectionIcon className="h-6 w-6 text-sky-600" />,
    },
    {
      id: "new-users",
      title: "ผู้ใช้งานใหม่",
      value: "86",
      trendLabel: "วันนี้",
      trendValue: "+9.7%",
      iconBg: "bg-amber-50",
      icon: <UserCircleIcon className="h-6 w-6 text-amber-500" />,
    },
  ];

  const products = [
    {
      id: 1,
      img: "/assets/images/products/s1.jpg",
      name: "ชาเขียวโฮจิฉะ",
      category: "ชาเขียว",
      price: 120,
      sold: 48,
    },
    {
      id: 2,
      img: "/assets/images/products/s2.jpg",
      name: "ชาไทยพรีเมียม",
      category: "ชาไทย",
      price: 95,
      sold: 65,
    },
    {
      id: 3,
      img: "/assets/images/products/s3.jpg",
      name: "โอวัลตินเย็น",
      category: "เมนูอื่น ๆ",
      price: 80,
      sold: 34,
    },
    {
      id: 4,
      img: "/assets/images/products/s4.jpg",
      name: "มัทฉะแฟรป",
      category: "มัทฉะ",
      price: 140,
      sold: 51,
    },
  ];

  return (
    <div className="min-h-screen flex bg-slate-50">
      <Sidebar
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
        handleLogout={handleLogout}
      />
      <div className="flex-1 flex flex-col">
        <Topbar />
        <DashboardContent stats={stats} products={products} />
      </div>
    </div>
  );
}
