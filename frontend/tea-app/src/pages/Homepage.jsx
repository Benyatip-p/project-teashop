import React from 'react'
import { Link } from 'react-router-dom'
import { ArrowRightIcon } from '@heroicons/react/outline'
import FeaturedTeas from '../components/FeaturedTeas'
import FeaturedCategories from '../components/FeaturedCategories'

const Homepage = () => {
  return (
    <div className="min-h-screen bg-white">
      <section className="relative w-full min-h-[420px] md:min-h-[520px] lg:min-h-[600px] flex items-center justify-center overflow-hidden">
        <img
          src="/images/headHomePage.jpg"
          alt="Good tea"
          className="absolute inset-0 w-full h-full object-cover"
        />

        <div className="absolute inset-0 bg-green-900/40" />

        <div className="relative z-10 mx-auto max-w-3xl px-4 text-center animate-fadeUp">
          <h1 className="text-4xl font-bold md:text-5xl text-white drop-shadow-lg">
            ค้นพบความงามของชาคุณภาพ
          </h1>

          <p className="mt-4 text-lg md:text-xl text-white drop-shadow-lg">
            จากสวนชาบนยอดเขาสู่ถ้วยชาของคุณ
          </p>

          <Link
            to="/products"
            className="group relative mt-8 inline-flex items-center justify-center px-10 py-4 rounded-xl font-semibold text-white bg-[#0b2f27] transition-all duration-300 hover:bg-[#13493d] hover:scale-[1.02] overflow-hidden"
          >
            <span className="relative z-10 tracking-wide">สำรวจสินค้า</span>

            <div className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/10 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
          </Link>
        </div>
      </section>

      <main className="bg-white">
        <div className="container mx-auto max-w-[1400px] px-8 pt-12 pb-20">
          <section className="mb-12 text-center">
            <h2 className="mt-2 text-xl md:text-2xl font-semibold text-gray-900">
              Good tea
            </h2>

            <div className="mt-3 max-w-3xl mx-auto text-base text-gray-700 leading-relaxed space-y-1">
              <p>เราศรัทธาในพลังที่เรียบง่ายของชาและความสงบที่มันมอบให้</p>
              <p>
                ทุกใบชาที่คัดสรรมาจากเรา ถูกตั้งใจส่งต่อให้คุณได้สัมผัสความผ่อนคลายและรสชาติที่แท้จริง
              </p>
            </div>
          </section>

          <section className="mb-16">
            <div className="text-center mb-3">
              <p className="text-xs font-medium tracking-[0.18em] text-viridian-500 uppercase">
                เลือกชาที่ใช่สำหรับคุณ
              </p>
            </div>

            <h2 className="text-2xl md:text-3xl font-semibold text-gray-900 mb-6">
              ประเภทของชา
            </h2>

            <FeaturedCategories />
          </section>

          <section className="mb-16 pb-4">
            <h2 className="text-2xl md:text-3xl font-semibold text-gray-900 mb-6">
              สินค้าแนะนำ
            </h2>

            <FeaturedTeas />
          </section>

          <div className="text-center">
            <Link
              to="/products"
              className="inline-flex items-center gap-2 bg-[#0b2f27] text-white text-lg font-semibold rounded-lg px-8 py-3 hover:bg-[#13493d] transition-colors"
            >
              ดูสินค้าทั้งหมด
              <ArrowRightIcon className="w-5 h-5" />
            </Link>
          </div>
        </div>
      </main>
    </div>
  )
}

export default Homepage
