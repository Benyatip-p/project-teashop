import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

const FeaturedCategories = () => {
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [imageErrors, setImageErrors] = useState({}); // เก็บสถานะรูปที่โหลดไม่ได้

  useEffect(() => {
    const fetchCategories = async () => {
      try {
        setLoading(true);
        
        // เรียก API เพื่อดึงข้อมูลหมวดหมู่แนะนำ
        const response = await fetch('/api/v1/categories/featured');
        console.log('Categories Response:', response);
        
        if (!response.ok) {
          throw new Error('Failed to fetch featured categories');
        }
        
        const data = await response.json();
        console.log('Categories Data received:', data);
        
        // ตรวจสอบว่าข้อมูลเป็น array หรือไม่
        let categoriesData = [];
        if (Array.isArray(data)) {
          categoriesData = data;
        } else if (data.categories && Array.isArray(data.categories)) {
          categoriesData = data.categories;
        } else if (data.data && Array.isArray(data.data)) {
          categoriesData = data.data;
        } else if (data.results && Array.isArray(data.results)) {
          categoriesData = data.results;
        } else {
          throw new Error('Invalid data format from API');
        }

        // แปลงข้อมูลให้ตรงกับโครงสร้างที่ใช้ใน frontend
        const formattedCategories = categoriesData.map(category => ({
          id: category.id,
          name: category.name || category.category_name,
          category: category.name || category.category_name,
          image: category.image_url || category.image || null,
          description: category.description || '',
          isActive: category.is_active !== false
        }));

        // กรองเฉพาะหมวดหมู่ที่ active
        const activeCategories = formattedCategories.filter(c => c.isActive);
        
        // จำกัดไม่เกิน 4 รายการ
        const selected = activeCategories.slice(0, 4);
        
        setCategories(selected);
        setError(null);
      } catch (err) {
        setError(err.message);
        console.error('Error fetching categories:', err);
      } finally {
        setLoading(false);
      }
    };

    // เรียกใช้ฟังก์ชันดึงข้อมูล
    fetchCategories();
  }, []);

  // ฟังก์ชันจัดการเมื่อรูปโหลดไม่ได้
  const handleImageError = (categoryId) => {
    setImageErrors(prev => ({
      ...prev,
      [categoryId]: true
    }));
  };

  // กรณีกำลังโหลดข้อมูล
  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[...Array(4)].map((_, index) => (
          <div key={index} className="bg-gray-200 rounded-lg overflow-hidden animate-pulse">
            <div className="aspect-square bg-gray-300"></div>
            <div className="p-4">
              <div className="h-4 bg-gray-300 rounded w-3/4 mx-auto"></div>
            </div>
          </div>
        ))}
      </div>
    );
  }

  // กรณีเกิดข้อผิดพลาด
  if (error) {
    return (
      <div className="text-center py-8 text-red-600">
        <p className="text-lg font-semibold">เกิดข้อผิดพลาด</p>
        <p className="text-sm">{error}</p>
      </div>
    );
  }

  // กรณีไม่มีข้อมูล
  if (categories.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <p>ไม่พบหมวดหมู่</p>
      </div>
    );
  }

  // กรณีแสดงผลข้อมูลปกติ
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {categories.map((category) => (
        <Link
          key={category.id}
          to={`/products?category=${category.category}`}
          className="bg-gray-100 rounded-lg overflow-hidden shadow hover:shadow-lg transition-shadow"
        >
          <div className="aspect-square bg-gray-300 flex items-center justify-center overflow-hidden">
            {category.image && !imageErrors[category.id] ? (
              <img
                src={category.image}
                alt={category.name}
                className="w-full h-full object-cover hover:scale-105 transition-transform duration-300"
                onError={() => handleImageError(category.id)}
              />
            ) : (
              <span className="text-4xl">🍵</span>
            )}
          </div>
          <div className="p-4 text-center bg-white">
            <h3 className="font-semibold text-gray-900">
              {category.name}
            </h3>
          </div>
        </Link>
      ))}
    </div>
  );
};

export default FeaturedCategories;