import React from "react";

const DashboardContent = ({ stats, products }) => {
  const activities = [
    {
      id: 1,
      type: "order",
      title: "สั่งซื้อใหม่: #10234",
      subtitle: "2 เมนู รวม 420 บาท",
      time: "2 ชั่วโมงที่แล้ว",
      badge: "A",
      badgeColor: "bg-emerald-100 text-emerald-700",
    },
    {
      id: 2,
      type: "product",
      title: "สินค้าเพิ่มสต็อก: มัทฉะแฟรป",
      subtitle: "เพิ่มสต็อก 30 แก้ว",
      time: "เมื่อวานนี้",
      badge: "P",
      badgeColor: "bg-sky-100 text-sky-700",
    },
    {
      id: 3,
      type: "promotion",
      title: "สร้างโปรโมชันใหม่: ชาอู่หลง",
      subtitle: "ส่วนลด 15% ถึงสิ้นเดือน",
      time: "2 วันก่อน",
      badge: "%",
      badgeColor: "bg-amber-100 text-amber-700",
    },
  ];

  return (
    <main className="flex-1">
      <div className="max-w-7xl mx-auto px-4 py-6 lg:px-8 lg:py-8">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between mb-6">
          <div>
            <h1 className="text-2xl font-semibold text-slate-900">
              แผงควบคุมร้านค้า
            </h1>
            <p className="text-sm text-slate-500 mt-1">
              ดูภาพรวมยอดขาย สต็อก และกิจกรรมล่าสุดของร้าน GOODTEA
            </p>
          </div>
          <div className="flex flex-wrap gap-3 justify-end">
            <button className="inline-flex items-center rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50">
              วันนี้
            </button>
            <button className="inline-flex items-center rounded-full bg-emerald-600 px-4 py-2 text-sm font-medium text-white shadow-md hover:bg-emerald-700">
              กลับไปหน้าร้าน
            </button>
          </div>
        </div>

        <section className="grid gap-4 md:grid-cols-3 mb-8">
          {stats.map((item) => (
            <div
              key={item.id}
              className="relative overflow-hidden rounded-2xl bg-white px-5 py-4 shadow-sm ring-1 ring-slate-100"
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-xs font-medium text-slate-400">
                    {item.title}
                  </p>
                  <p className="mt-2 text-2xl font-semibold text-slate-900">
                    {item.value}
                  </p>
                  <div className="mt-2 flex items-center gap-2">
                    <span className="inline-flex items-center rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700">
                      {item.trendValue}
                    </span>
                    <span className="text-xs text-slate-400">
                      {item.trendLabel}
                    </span>
                  </div>
                </div>
                <div
                  className={`flex h-10 w-10 items-center justify-center rounded-xl ${item.iconBg}`}
                >
                  {item.icon}
                </div>
              </div>
            </div>
          ))}
        </section>

        <section className="grid gap-6 lg:grid-cols-3 mb-8">
          <div className="lg:col-span-2 rounded-2xl bg-white p-5 shadow-sm ring-1 ring-slate-100">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  สรุปยอดขายประจำเดือน
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  พื้นที่สำหรับใส่กราฟจาก Chart library ภายหลัง
                </p>
              </div>
              <span className="text-xs font-medium text-emerald-600">
                ดูรายงาน
              </span>
            </div>
            <div className="flex h-56 items-center justify-center rounded-xl border border-dashed border-slate-200 bg-slate-50 text-xs text-slate-400">
              กราฟยอดขายจะอยู่ตรงนี้
            </div>
          </div>

          <div className="rounded-2xl bg-white p-5 shadow-sm ring-1 ring-slate-100 flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-slate-900">
                สินค้าขายดีวันนี้
              </h2>
              <button className="text-xs font-medium text-emerald-600 hover:text-emerald-700">
                เพิ่มสินค้า
              </button>
            </div>
            <div className="space-y-3">
              {products.map((product, index) => (
                <div
                  key={product.id}
                  className="flex items-center gap-3 rounded-xl px-2 py-2 hover:bg-slate-50"
                >
                  <div className="h-12 w-12 flex-shrink-0 overflow-hidden rounded-xl bg-slate-100 ring-1 ring-slate-200">
                    <img
                      src={product.img}
                      alt={product.name}
                      className="h-full w-full object-cover"
                    />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-slate-400">
                      อันดับ {index + 1} · {product.category}
                    </p>
                    <p className="truncate text-sm font-medium text-slate-900">
                      {product.name}
                    </p>
                    <div className="mt-0.5 flex items-center gap-2">
                      <p className="text-xs font-medium text-emerald-700">
                        ฿{product.price}
                      </p>
                      <p className="text-[11px] text-slate-400">
                        ขายแล้ว {product.sold} แก้ว
                      </p>
                    </div>
                  </div>
                  <span className="inline-flex items-center rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700">
                    ดูรายละเอียด
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="grid gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2 rounded-2xl bg-white p-5 shadow-sm ring-1 ring-slate-100">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-slate-900">
                กิจกรรมล่าสุด
              </h2>
              <button className="text-xs font-medium text-emerald-600 hover:text-emerald-700">
                ดูทั้งหมด
              </button>
            </div>
            <div className="space-y-3">
              {activities.map((activity) => (
                <div
                  key={activity.id}
                  className="flex items-start gap-3 rounded-xl px-2 py-2 hover:bg-slate-50"
                >
                  <div
                    className={`mt-0.5 inline-flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold ${activity.badgeColor}`}
                  >
                    {activity.badge}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-slate-900">
                      {activity.title}
                    </p>
                    <p className="text-xs text-slate-500">
                      {activity.subtitle}
                    </p>
                  </div>
                  <p className="whitespace-nowrap text-xs text-slate-400">
                    {activity.time}
                  </p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-2xl bg-white p-5 shadow-sm ring-1 ring-slate-100">
            <h2 className="mb-4 text-sm font-semibold text-slate-900">
              ภาพรวมวันนี้
            </h2>
            <div className="space-y-4 text-sm text-slate-700">
              <div className="flex items-center justify-between">
                <span>ออเดอร์ทั้งหมด</span>
                <span className="font-semibold">32 ออเดอร์</span>
              </div>
              <div className="flex items-center justify-between">
                <span>ออเดอร์ที่สำเร็จ</span>
                <span className="font-semibold text-emerald-700">28</span>
              </div>
              <div className="flex items-center justify-between">
                <span>ออเดอร์ที่รอชำระ</span>
                <span className="font-semibold text-amber-600">3</span>
              </div>
              <div className="flex items-center justify-between">
                <span>ออเดอร์ที่ยกเลิก</span>
                <span className="font-semibold text-rose-600">1</span>
              </div>
              <div className="pt-3 border-t border-slate-100">
                <p className="text-xs text-slate-400">
                  ข้อมูลตัวอย่าง สามารถเชื่อมต่อกับ API รายงานจริงได้ภายหลัง
                </p>
              </div>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
};

export default DashboardContent;
