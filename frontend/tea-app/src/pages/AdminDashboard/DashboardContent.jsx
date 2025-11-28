// src/pages/AdminDashboard/DashboardContent.jsx
import React from 'react'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts'

const DashboardContent = ({
  stats,
  products,
  salesChartData,
  salesLoading,
  salesError,
}) => {
  const activities = [
    {
      id: 1,
      type: 'order',
      title: 'สั่งซื้อใหม่: #10234',
      subtitle: '2 เมนู รวม 420 บาท',
      time: '2 ชั่วโมงที่แล้ว',
      badge: 'A',
      badgeColor: 'bg-emerald-100 text-emerald-700',
    },
    {
      id: 2,
      type: 'product',
      title: 'สินค้าเพิ่มสต็อก: มัทฉะแฟรป',
      subtitle: 'เพิ่มสต็อก 30 แก้ว',
      time: 'เมื่อวานนี้',
      badge: 'P',
      badgeColor: 'bg-sky-100 text-sky-700',
    },
    {
      id: 3,
      type: 'promotion',
      title: 'สร้างโปรโมชันใหม่: ชาอู่หลง',
      subtitle: 'ส่วนลด 15% ถึงสิ้นเดือน',
      time: '2 วันก่อน',
      badge: '%',
      badgeColor: 'bg-amber-100 text-amber-700',
    },
  ]

  const formatCurrencyTick = (value) =>
    Number(value || 0).toLocaleString('th-TH', {
      maximumFractionDigits: 0,
    })

  const formatTooltip = (value) =>
    Number(value || 0).toLocaleString('th-TH', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })

  const formatShortCurrency = (value) =>
    `฿${Number(value || 0).toLocaleString('th-TH', {
      maximumFractionDigits: 0,
    })}`

  return (
    <main className="flex-1">
      <div className="mx-auto max-w-7xl px-4 py-6 lg:px-8 lg:py-8">
        <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-slate-900">
              แผงควบคุมร้านค้า
            </h1>
            <p className="mt-1 text-sm text-slate-500">
              ดูภาพรวมยอดขาย สต็อก และกิจกรรมล่าสุดของร้าน GOODTEA
            </p>
          </div>
          <div className="flex flex-wrap justify-end gap-3">
            <button className="inline-flex items-center rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50">
              วันนี้
            </button>
            <button className="inline-flex items-center rounded-full bg-emerald-600 px-4 py-2 text-sm font-medium text-white shadow-md hover:bg-emerald-700">
              กลับไปหน้าร้าน
            </button>
          </div>
        </div>

        <section className="mb-8 grid gap-4 md:grid-cols-3">
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
                  {item.trendLabel && (
                    <div className="mt-2 flex items-center gap-2">
                      {item.trendValue && (
                        <span className="inline-flex items-center rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700">
                          {item.trendValue}
                        </span>
                      )}
                      <span className="text-xs text-slate-400">
                        {item.trendLabel}
                      </span>
                    </div>
                  )}
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

        <section className="mb-8 grid gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2 overflow-hidden rounded-2xl bg-gradient-to-br from-emerald-50 via-white to-sky-50 p-5 shadow-sm ring-1 ring-emerald-100/60">
            <div className="mb-4 flex items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  สรุปยอดขายทางการเงิน
                </h2>
                <p className="mt-1 text-xs text-slate-500">
                  ยอดขายวันนี้ เดือนนี้ และปีนี้ ในมุมมองเดียว
                </p>
              </div>
              <button className="rounded-full bg-white/80 px-3 py-1 text-xs font-medium text-emerald-700 shadow-sm ring-1 ring-emerald-100 hover:bg-white">
                ดูรายงานละเอียด
              </button>
            </div>

            <div className="mb-4 grid gap-3 text-xs text-slate-700 sm:grid-cols-3">
              {salesChartData.map((item) => (
                <div
                  key={item.label}
                  className="flex items-center justify-between rounded-xl bg-white/80 px-3 py-2 shadow-sm ring-1 ring-emerald-50"
                >
                  <div className="flex flex-col">
                    <span className="text-[11px] text-slate-400">
                      {item.label}
                    </span>
                    <span className="mt-1 text-sm font-semibold text-slate-900">
                      {formatShortCurrency(item.value)}
                    </span>
                  </div>
                  <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-medium text-emerald-700">
                    ยอดรวม
                  </span>
                </div>
              ))}
            </div>

            <div className="h-56 rounded-2xl bg-white/80 px-3 py-3 shadow-sm ring-1 ring-emerald-50">
              {salesLoading && (
                <div className="flex h-full items-center justify-center text-xs text-slate-400">
                  กำลังโหลดข้อมูลยอดขาย...
                </div>
              )}
              {!salesLoading && salesError && (
                <div className="flex h-full items-center justify-center text-xs text-red-500">
                  {salesError}
                </div>
              )}
              {!salesLoading && !salesError && (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={salesChartData}
                    margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
                    barCategoryGap={32}
                  >
                    <defs>
                      <linearGradient id="salesGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#10b981" stopOpacity={0.95} />
                        <stop offset="100%" stopColor="#22c55e" stopOpacity={0.75} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      vertical={false}
                      stroke="#e2e8f0"
                    />
                    <XAxis
                      dataKey="label"
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 11, fill: '#64748b' }}
                    />
                    <YAxis
                      tickFormatter={formatCurrencyTick}
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 11, fill: '#94a3b8' }}
                    />
                    <Tooltip
                      cursor={{ fill: 'rgba(16, 185, 129, 0.06)' }}
                      contentStyle={{
                        borderRadius: 12,
                        borderColor: '#d1fae5',
                        boxShadow:
                          '0 10px 25px rgba(15, 23, 42, 0.08)',
                        fontSize: 12,
                      }}
                      formatter={(value) => [
                        `฿${formatTooltip(value)}`,
                        'ยอดขาย',
                      ]}
                    />
                    <Bar
                      dataKey="value"
                      radius={[10, 10, 4, 4]}
                      fill="url(#salesGradient)"
                    />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="flex flex-col rounded-2xl bg-white p-5 shadow-sm ring-1 ring-slate-100">
            <div className="mb-4 flex items-center justify-between">
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
                  <div className="min-w-0 flex-1">
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
            <div className="mb-4 flex items-center justify-between">
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
                  <div className="min-w-0 flex-1">
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
              <div className="border-t border-slate-100 pt-3">
                <p className="text-xs text-slate-400">
                  ข้อมูลตัวอย่าง สามารถเชื่อมต่อกับ API รายงานจริงได้ภายหลัง
                </p>
              </div>
            </div>
          </div>
        </section>
      </div>
    </main>
  )
}

export default DashboardContent
