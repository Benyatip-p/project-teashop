import React from "react";

const StatCard = ({ title, value, icon }) => (
  <div className="bg-white p-5 rounded-xl shadow-sm border">
    <div className="flex items-start justify-between">
      <div>
        <p className="text-sm text-gray-500">{title}</p>
        <p className="text-2xl font-semibold mt-2">{value}</p>
      </div>
      <div className="h-12 w-12 bg-gray-100 rounded-lg flex items-center justify-center">
        {icon}
      </div>
    </div>
  </div>
);

export default StatCard;
