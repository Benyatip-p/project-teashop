import React from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeftIcon } from "@heroicons/react/outline";

export default function Topbar({ title }) {
  const navigate = useNavigate();

  return (
    <div className="flex w-full items-center justify-between bg-white px-6 py-4 shadow-sm">
      <h1 className="text-xl font-semibold text-gray-800">{title}</h1>

      <button
        onClick={() => navigate("/")}
        className="flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-white shadow hover:bg-emerald-700 transition"
      >
        <ArrowLeftIcon className="h-5 w-5" />
        กลับไปหน้าร้าน
      </button>
    </div>
  );
}
