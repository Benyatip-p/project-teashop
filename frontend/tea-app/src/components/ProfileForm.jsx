import React, { useState, useEffect } from 'react';
import api from '../api/api';

const ProfileForm = () => {
  const [gender, setGender] = useState('male');
  const [user, setUser] = useState({ username: '' });

  // Fetch user profile data
  const fetchProfile = async () => {
    try {
      const response = await api.get('/profile');
      setUser(response.data);
    } catch (error) {
      console.error('Failed to fetch profile:', error);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  return (
    <div className="flex-1 bg-white p-6 shadow-sm rounded-sm min-h-[500px]">
      {/* Header */}
      <div className="border-b border-gray-200 pb-4 mb-8">
        <h1 className="text-xl font-medium text-gray-800">ข้อมูลของฉัน</h1>
        <p className="text-sm text-gray-500 mt-1">จัดการข้อมูลส่วนตัวคุณเพื่อความปลอดภัยของบัญชีผู้ใช้นี้</p>
      </div>

      <div className="flex flex-col-reverse md:flex-row gap-8">
        {/* Left Side: Form Inputs */}
        <div className="flex-1 pr-0 md:pr-12">
          <form className="space-y-8">
            
            {/* Username */}
            <div className="flex flex-col md:flex-row md:items-center">
              <label className="w-32 text-left md:text-right pr-4 text-gray-500 text-sm mb-1 md:mb-0">ชื่อผู้ใช้</label>
              <div className="text-gray-800 text-sm">{user.username || 'Loading...'}</div>
            </div>

            {/* Name Input */}
            <div className="flex flex-col md:flex-row md:items-center">
              <label className="w-32 text-left md:text-right pr-4 text-gray-500 text-sm mb-1 md:mb-0">ชื่อ</label>
              <input type="text" className="border border-gray-300 rounded-sm px-3 py-2 w-full text-sm focus:outline-none focus:border-gray-500 shadow-sm" defaultValue="" />
            </div>

            {/* Email */}
            <div className="flex flex-col md:flex-row md:items-center">
              <label className="w-32 text-left md:text-right pr-4 text-gray-500 text-sm mb-1 md:mb-0">อีเมล</label>
              <div className="text-sm">
                <span className="text-gray-800">tj*********@gmail.com</span>
                <a href="#" className="ml-2 text-blue-500 underline text-xs font-medium">เปลี่ยน</a>
              </div>
            </div>

            {/* Phone */}
            <div className="flex flex-col md:flex-row md:items-center">
              <label className="w-32 text-left md:text-right pr-4 text-gray-500 text-sm mb-1 md:mb-0">หมายเลขโทรศัพท์</label>
              <div className="text-sm">
                <span className="text-gray-800">*********32</span>
                <a href="#" className="ml-2 text-blue-500 underline text-xs font-medium">เปลี่ยน</a>
              </div>
            </div>

            {/* Gender Radio */}
            <div className="flex flex-col md:flex-row md:items-center">
              <label className="w-32 text-left md:text-right pr-4 text-gray-500 text-sm mb-1 md:mb-0">เพศ</label>
              <div className="flex gap-4">
                <label className="flex items-center cursor-pointer">
                  <input 
                    type="radio" 
                    name="gender" 
                    checked={gender === 'male'} 
                    onChange={() => setGender('male')}
                    className="mr-2 text-orange-500 focus:ring-orange-500" 
                  />
                  <span className="text-sm text-gray-700">ชาย</span>
                </label>
                <label className="flex items-center cursor-pointer">
                  <input 
                    type="radio" 
                    name="gender" 
                    checked={gender === 'female'} 
                    onChange={() => setGender('female')}
                    className="mr-2 text-orange-500 focus:ring-orange-500" 
                  />
                  <span className="text-sm text-gray-700">หญิง</span>
                </label>
                <label className="flex items-center cursor-pointer">
                  <input 
                    type="radio" 
                    name="gender" 
                    checked={gender === 'other'} 
                    onChange={() => setGender('other')}
                    className="mr-2 text-orange-500 focus:ring-orange-500" 
                  />
                  <span className="text-sm text-gray-700">อื่น ๆ</span>
                </label>
              </div>
            </div>

            {/* Birth Date */}
            <div className="flex flex-col md:flex-row md:items-center">
              <label className="w-32 text-left md:text-right pr-4 text-gray-500 text-sm mb-1 md:mb-0">วัน/เดือน/ปี เกิด</label>
              <div className="flex gap-2 w-full max-w-sm">
                <select className="border border-gray-300 rounded-sm px-3 py-2 w-full text-sm text-gray-500 bg-white focus:outline-none focus:border-gray-500">
                    <option>Date</option>
                </select>
                <select className="border border-gray-300 rounded-sm px-3 py-2 w-full text-sm text-gray-500 bg-white focus:outline-none focus:border-gray-500">
                    <option>เดือน</option>
                </select>
                <select className="border border-gray-300 rounded-sm px-3 py-2 w-full text-sm text-gray-500 bg-white focus:outline-none focus:border-gray-500">
                    <option>ปี</option>
                </select>
              </div>
            </div>

            {/* Submit Button */}
            <div className="flex md:pl-32 mt-8">
              <button className="bg-[#ee4d2d] text-white px-6 py-2 rounded-sm text-sm hover:bg-[#d73211] transition-colors shadow-sm">
                บันทึก
              </button>
            </div>

          </form>
        </div>
      </div>
    </div>
  );
};

export default ProfileForm;