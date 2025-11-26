import React from 'react'

const Aboutpage = () => {
  return (
    <div className="min-h-screen bg-[#f5f7f5]">

      {/* --- Hero Section --- */}
      <div className="w-full h-64 md:h-80 relative">
        <img
          src="/images/headAboutPage.jpg"
          alt="About Us"
          className="w-full h-full object-cover"
        />
        <div className="absolute inset-0 bg-black/20" />
        <h1 className="absolute inset-0 flex items-center justify-center text-white text-4xl md:text-5xl font-semibold tracking-wide drop-shadow-lg">
          About Us
        </h1>
      </div>

      {/* --- Content Section --- */}
      <div className="py-14">
        <div className="container mx-auto px-4">
          <div className="max-w-4xl mx-auto">

            {/* Divider */}
            <div className="w-20 h-[3px] bg-viridian-700 rounded-full mx-auto mb-8"></div>

            <h2 className="text-center text-3xl font-bold text-gray-900">
              Good Tea
            </h2>

            <p className="mt-2 text-center text-gray-500">
              ร้านชาเพื่อคนรักชาแบบตัวจริง
            </p>

            <div className="mt-10 space-y-6 text-lg leading-relaxed text-gray-700">

              <p>
                ยินดีต้อนรับสู่ <span className="font-semibold">บริษัท กู๊ดที จำกัด</span>  
                เราเริ่มต้นจากความหลงใหลในเสน่ห์ของชา และความสุขเล็ก ๆ ที่ได้จากการชงชาดื่มด้วยตัวเอง  
                เราเชื่อว่า “การชงชา” ไม่ใช่แค่กิจกรรม แต่คือพื้นที่สงบเล็ก ๆ ที่ช่วยให้ใจได้พักอย่างแท้จริง
              </p>

              <p>
                ที่ GoodTea เราคัดสรรใบชาคุณภาพ จากไร่ชาชั้นดีทั้งในไทยและต่างประเทศ  
                ตั้งแต่ใบชาหายากไปจนถึงใบชาที่เหมาะสำหรับดื่มทุกวัน พร้อมอุปกรณ์ชงชาที่ครบครัน  
                เพราะเรารู้ว่ารสชาติของชาไม่ได้มาจากวัตถุดิบเท่านั้น แต่รวมถึงกระบวนการชงทั้งหมด
              </p>

              <p>
                เรามุ่งมั่นที่จะพัฒนาคุณภาพต่อไป น้อมรับคำติชม และยังคงเดินหน้าตามหาชาที่ดีที่สุด  
                เพื่อให้ทุกคนได้สัมผัสประสบการณ์แห่งการพักผ่อนผ่าน “ชาแก้วที่ดีที่สุด” จากใจของเรา
              </p>

            </div>

          </div>
        </div>
      </div>

    </div>
  )
}

export default Aboutpage
