import React, { useState, useEffect } from 'react';
import TeaCard from './ProductCard';
import { ChevronLeftIcon, ChevronRightIcon } from '@heroicons/react/outline';

const FeaturedTeas = () => {
  const [featuredTeas, setFeaturedTeas] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [currentIndex, setCurrentIndex] = useState(0);

  // Static category mapping
  const categoryIdToName = {
    3: 'กาชงชา',
    4: 'ชาเขียว',
    5: 'ชาอู่หลง',
    6: 'ชาดำ',
    7: 'ชาขาว',
    8: 'อุปกรณ์กรองชา',
    9: 'ถ้วยชา',
  };

  useEffect(() => {
    const fetchTeas = async () => {
      try {
        setLoading(true);
        
        // Fetch featured products
        console.log('Fetching featured teas from API');
        const response = await fetch('/api/v1/products/featured');
        console.log('Response:', response);
        
        if (!response.ok) {
          throw new Error('Failed to fetch products');
        }
        
        const data = await response.json();
        console.log('Data received:', data);
        
        // ตรวจสอบว่าข้อมูลเป็น array หรือไม่
        let products = [];
        if (Array.isArray(data)) {
          products = data;
        } else if (data.products && Array.isArray(data.products)) {
          products = data.products;
        } else if (data.data && Array.isArray(data.data)) {
          products = data.data;
        } else if (data.results && Array.isArray(data.results)) {
          products = data.results;
        } else {
          throw new Error('Invalid data format from API');
        }

        // แปลงข้อมูลให้ตรงกับโครงสร้างที่ใช้ใน frontend
        const formattedProducts = products.map(product => ({
          id: product.id,
          title: product.name,
          name: product.name,
          category: categoryIdToName[product.category_id] || 'ทั่วไป', // ✅ ใช้ static mapping
          categoryId: product.category_id,
          brand: product.brand || 'Tea House',
          price: parseFloat(product.price),
          originalPrice: product.original_price ? parseFloat(product.original_price) : null,
          coverImage: product.image_url
            ? `/${product.image_url}`
            : '/images/placeholder.jpg',
          rating: product.rating || 0,
          reviews: product.reviews_count || product.reviews || 0,
          discount: product.discount_percentage || product.discount || null,
          stock: product.stock,
          description: product.description || '',
          isActive: product.is_active !== false,
          isNew: product.is_new || false,
          createdAt: product.created_at,
          updatedAt: product.updated_at
        }));

        // กรองเฉพาะสินค้าที่ active
        const activeProducts = formattedProducts.filter(p => p.isActive);
        
        setFeaturedTeas(activeProducts);
        setError(null);
      } catch (err) {
        setError(err.message);
        console.error('Error fetching products:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchTeas();
  }, []);

  // ฟังก์ชันเลื่อนไปหน้า
  const handleNext = () => {
    if (currentIndex < featuredTeas.length - 4) {
      setCurrentIndex(currentIndex + 1);
    }
  };

  // ฟังก์ชันเลื่อนกลับ
  const handlePrev = () => {
    if (currentIndex > 0) {
      setCurrentIndex(currentIndex - 1);
    }
  };

  // คำนวณสินค้าที่จะแสดง (4 รายการ)
  const visibleProducts = featuredTeas.slice(currentIndex, currentIndex + 4);

  // คำนวณจำนวนหน้า
  const totalPages = Math.max(0, featuredTeas.length - 3);

  // กรณีกำลังโหลดข้อมูล
  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[...Array(4)].map((_, index) => (
          <div key={index} className="bg-gray-200 rounded-lg overflow-hidden animate-pulse">
            <div className="aspect-square bg-gray-300"></div>
            <div className="p-3">
              <div className="h-4 bg-gray-300 rounded mb-2"></div>
              <div className="h-4 bg-gray-300 rounded w-2/3"></div>
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
  if (featuredTeas.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <p>ไม่พบสินค้า</p>
      </div>
    );
  }

  return (
    <div className="relative">
      <div className="relative flex items-center gap-4">
        {/* Left Arrow */}
        <button 
          onClick={handlePrev}
          disabled={currentIndex === 0}
          className={`absolute left-0 z-10 -ml-4 md:-ml-6 bg-white p-3 rounded-full shadow-lg transition-all border border-gray-300 ${
            currentIndex === 0 
              ? 'opacity-50 cursor-not-allowed' 
              : 'hover:bg-gray-100 cursor-pointer'
          }`}
          aria-label="Previous"
        >
          <ChevronLeftIcon className="w-6 h-6 text-gray-700" />
        </button>

        {/* Products Grid */}
        <div className="flex-1 overflow-hidden px-8 md:px-12">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 transition-all duration-300">
            {visibleProducts.map((product) => (
              <TeaCard
                key={product.id}
                product={product}
              />
            ))}
          </div>
        </div>

        {/* Right Arrow */}
        <button 
          onClick={handleNext}
          disabled={currentIndex >= featuredTeas.length - 4}
          className={`absolute right-0 z-10 -mr-4 md:-mr-6 bg-white p-3 rounded-full shadow-lg transition-all border border-gray-300 ${
            currentIndex >= featuredTeas.length - 4
              ? 'opacity-50 cursor-not-allowed' 
              : 'hover:bg-gray-100 cursor-pointer'
          }`}
          aria-label="Next"
        >
          <ChevronRightIcon className="w-6 h-6 text-gray-700" />
        </button>
      </div>

      {/* Indicator dots */}
      {totalPages > 0 && (
        <div className="flex justify-center gap-2 mt-4">
          {Array.from({ length: totalPages }).map((_, index) => (
            <button
              key={index}
              onClick={() => setCurrentIndex(index)}
              className={`w-2 h-2 rounded-full transition-all ${
                currentIndex === index ? 'bg-green-600 w-6' : 'bg-gray-300'
              }`}
              aria-label={`Go to page ${index + 1}`}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default FeaturedTeas;