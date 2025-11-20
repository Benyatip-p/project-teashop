import React from 'react'

const Aboutpage = () => {
     return (
          <div className='min-h-screen bg-gray-50'>

               {/* --- Hero Section --- */}
               {/* ใช้ h-96 (24rem) หรือค่าอื่นที่เหมาะสม */}
               <div className="w-full h-64 bg-gray-200">
                    <img
                         src="/images/headAboutPage.jpg"
                         alt="About Us Hero"
                         className="w-full h-full object-cover"
                    />
               </div>

               {/* --- Content Section --- */}
               <div className='py-12'>
                    <div className='container mx-auto px-4'>
                         <div className='max-w-6xl mx-auto'>

                              {/* เนื้อหาอื่นๆ ของหน้า About Us ใส่ตรงนี้ */}
                              <h1 className="text-4xl font-bold">About Us</h1>

                              <div className="mt-6 space-y-4 text-lg text-gray-700">
                                   <p>
                                        ยินดีต้อนรับสู่ บริษัท กู๊ดที จำกัด
                                   </p>
                                   <p>
                                        เราเริ่มต้นจากการเป็นคนหนึ่งที่หลงใหลในเสน่ห์ของชา... และเราเชื่อว่าการชงชาดื่มเองสักกา เป็นการบำบัดจิตใจที่ง่ายและดีที่สุด 
                                        และยังค้นพบว่า ความสุขไม่ได้อยู่แค่ที่รสชาติของชา แต่อยู่ที่ "กระบวนการ" ทั้งหมด
                                        ที่กู๊ดทีเราคัดสรรทุกอย่างด้วยความรัก เรามีตั้งแต่ใบชาหายากไปจนถึงชาสำหรับดื่มทุกวัน และเรามีอุปกรณ์ชงชาที่หลากหลาย
                                   </p>
                                   <p>
                                        บริษัทกู๊ดทีมีความมุ่งมันที่จะเป็นผู้นำที่นำส่งชาที่ดีที่สุดให้แก่ลูกค้า โดยน้อมรับคำติชมต่าง ๆ และยืนหยัดจะรักษาและตามหาชาดี ๆ ต่อไป
                                   </p>
                              </div>

                         </div>
                    </div>
               </div>
          </div>
     )
}

export default Aboutpage;