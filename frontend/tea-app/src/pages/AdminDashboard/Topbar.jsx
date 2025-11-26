import React from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeftIcon } from "@heroicons/react/outline";

export default function Topbar() {
  const navigate = useNavigate();

  return (
    <div className="w-full bg-white shadow-sm px-6 py-4 flex items-center justify-between">
      <h1 className="text-xl font-semibold text-gray-800">
        แผงควบคุมร้านค้า (Dashboard)
      </h1>

      <button
        onClick={() => navigate("/")}
        className="flex items-center gap-2 bg-emerald-600 text-white px-4 py-2 rounded-lg shadow hover:bg-emerald-700 transition"
      >
        <ArrowLeftIcon className="h-5 w-5" />
        กลับไปหน้าร้าน
      </button>
    </div>
  );
}
