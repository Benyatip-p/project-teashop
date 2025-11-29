import React, { useState, useEffect } from 'react';

const TOKEN_KEY = 'access_token';

const ProfileForm = () => {
  const [user, setUser] = useState({
    username: '',
    email: '',
  });

  // State สำหรับจัดการ UI
  const [loading, setLoading] = useState(true); // กำลังโหลดข้อมูลครั้งแรก
  const [saving, setSaving] = useState(false);   // กำลังบันทึกข้อมูล
  const [error, setError] = useState(null);       // เก็บข้อความ Error

  // --- 1. ดึงข้อมูลโปรไฟล์มาแสดงเมื่อ Component โหลด ---
  useEffect(() => {
    const fetchProfile = async () => {
      setLoading(true);
      setError(null);
      
      const token = localStorage.getItem(TOKEN_KEY);
      if (!token) {
        setError("ไม่พบ Token สำหรับการยืนยันตัวตน กรุณาเข้าสู่ระบบใหม่");
        setLoading(false);
        return;
      }

      try {
        const response = await fetch('/api/v1/profile', {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`, // แนบ Token ไปกับ Request
          },
        });

        if (!response.ok) {
          // ถ้า response status ไม่ใช่ 2xx (เช่น 401, 404, 500)
          const errorData = await response.json().catch(() => ({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูล' }));
          throw new Error(errorData.message || `Error: ${response.status}`);
        }

        const data = await response.json();
        
        // อัปเดต state ด้วยข้อมูลที่ได้จาก API (ป้องกันค่า null)
        setUser({
          username: data.username || '',
          name: data.name || '',
          email: data.email || '',
        });

      } catch (err) {
        console.error('Failed to fetch profile:', err);
        setError('ไม่สามารถโหลดข้อมูลโปรไฟล์ได้');
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, []); // [] หมายถึงให้ useEffect นี้ทำงานแค่ครั้งเดียวตอนเริ่มต้น

  // --- 2. ฟังก์ชันจัดการการเปลี่ยนแปลงในฟอร์ม ---
  const handleChange = (e) => {
    const { name, value } = e.target;
    setUser((prev) => ({ ...prev, [name]: value }));
  };

  // --- 3. ฟังก์ชันบันทึกข้อมูล (ส่งกลับไปที่ API) ---
  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) {
        alert("ไม่พบ Token สำหรับการยืนยันตัวตน กรุณาเข้าสู่ระบบใหม่");
        setSaving(false);
        return;
    }

    // เตรียมข้อมูลที่จะส่ง (ไม่ส่ง username เพราะมักจะแก้ไขไม่ได้)
    const payload = {
      name: user.name,
      email: user.email,
    };

    try {
      const response = await fetch('/api/v1/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`, // แนบ Token
        },
        body: JSON.stringify(payload), // แปลง object เป็น JSON string
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'เกิดข้อผิดพลาดในการบันทึก' }));
        throw new Error(errorData.message || `Error: ${response.status}`);
      }
      
      const updatedData = await response.json();
      console.log('Profile updated:', updatedData);

      // อัปเดต State ด้วยข้อมูลที่เซิร์ฟเวอร์ตอบกลับมา เพื่อความถูกต้อง
      setUser(prev => ({ ...prev, ...updatedData }));

      alert('บันทึกข้อมูลสำเร็จ!');

    } catch (err) {
      console.error('Failed to update profile:', err);
      alert(`ไม่สามารถบันทึกข้อมูลได้: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };


  // --- ส่วนของการแสดงผล (UI) ---
  
  if (loading) {
    return <div className="p-8 text-center text-gray-500">กำลังโหลดข้อมูล...</div>;
  }

  if (error) {
    return <div className="p-8 text-center text-red-600 bg-red-50 rounded-lg">{error}</div>;
  }
  
  const inputClass = "border border-gray-300 rounded-md px-3 py-2 w-full text-sm focus:outline-none focus:ring-1 ";
  
  return (
    <div className="bg-white p-6 md:p-10">
      <div className="border-b border-gray-200 pb-4 mb-8">
        <h1 className="text-xl font-medium text-gray-800">ข้อมูลของฉัน</h1>
        <p className="text-sm text-gray-500 mt-1">
          จัดการข้อมูลส่วนตัวคุณเพื่อความปลอดภัยของบัญชีผู้ใช้นี้
        </p>
      </div>

      <form className="max-w-2xl" onSubmit={handleSubmit}>
        <div className="space-y-6">
          
          {/* Username (แสดงอย่างเดียว) */}
          <div className="flex items-center">
            <label className="w-40 text-right pr-8 text-gray-600 shrink-0">
              ชื่อผู้ใช้
            </label>
            <div className="text-gray-900 bg-gray-100 px-3 py-2 rounded-md w-full cursor-not-allowed">
              {user.username || '-'}
            </div>
          </div>

          {/* Email */}
          <div className="flex items-center">
            <label 
              htmlFor="email" 
              className="w-40 text-right pr-8 text-gray-600 shrink-0"
            >
              อีเมล
            </label>
            <input
              id="email"
              type="email"
              name="email"
              value={user.email}
              readOnly   // <-- เพิ่มตรงนี้
              className="bg-gray-100 text-gray-900 px-3 py-2 rounded-md w-full cursor-not-allowed"
            />
          </div>
          {/* Submit Button */}
          <button
            type="submit"
            disabled
            className="w-full rounded-xl py-3 text-sm font-semibold text-white transition-colors 
                      bg-gray-400 cursor-not-allowed opacity-60"
          >
            บันทึก
          </button>
        </div>
      </form>
    </div>
  );
};

export default ProfileForm;  