import React from 'react'
import { Link } from 'react-router-dom';
import { ArrowRightIcon } from '@heroicons/react/outline';
import FeaturedTeas from '../components/FeaturedTeas'; 
import FeaturedCategories from '../components/FeaturedCategories';

const Homepage = () => {
  return (
    <div className="min-h-screen bg-white">
      {/* Hero Image */}
      <section className="w-full h-64 md:h-80">
        <img
          src="/images/headHomePage.jpg"
          alt="Good tea"
          className="w-full h-full object-cover"
        />
      </section>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-8 bg-white">
        
        {/* Title */}
        <h1 className="text-3xl font-bold mb-8 text-gray-900">
          Good tea
        </h1>
        <h4 className="text-xl font-normal mb-8 text-gray-900">
          <p>เราเริ่มต้นจากการเป็นคนหนึ่งที่หลงใหลในเสน่ห์ของชา... 
          </p>
          <p>ราเชื่อว่าการชงชาดื่มเองสักกาเป็นการบำบัดจิตใจที่ง่ายและดีที่สุด และยังค้นพบว่าความสุขไม่ได้อยู่แค่ที่รสชาติของชา
          </p>
        </h4>

        {/* Tea Categories - ใช้ Component */}
        <section className="mb-12">
          <h2 className="text-xl font-bold mb-6 text-gray-900">
            ประเภทของชา
          </h2>
          
          {/* ใช้ FeaturedCategories Component */}
          <FeaturedCategories />
        </section>

        {/* Featured Products - ใช้ Component */}
        <section className="mb-12">
          <h2 className="text-xl font-bold mb-6 text-gray-900">
            สินค้าแนะนำ
          </h2>
          
          {/* ใช้ FeaturedTeas Component */}
          <FeaturedTeas />
        </section>

        {/* View All Button */}
        <div className="text-center mb-12">
          <Link
            to="/products"
            className="inline-flex items-center gap-2 bg-green-700 text-white px-8 py-3 rounded-lg hover:bg-green-800 transition-colors font-semibold text-lg"
          >
            ดูสินค้าทั้งหมด
            <ArrowRightIcon className="w-5 h-5" />
          </Link>
        </div>

      </div>
    </div>
  )
}

export default Homepage;