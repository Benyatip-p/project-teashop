// src/pages/AdminDashboard/DashboardContent.jsx
import React, { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
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
  userStats,
  monthlyHistory = [],
  yearlyHistory = [],
  orderStatusDistribution = [],
  averageOrderValue = 0,
  totalProductsCount = 0,
  revenueByCategory = [],
  recentActivities = [],
}) => {
  const [overviewMode, setOverviewMode] = useState('year')

  const activities = recentActivities

  const formatCurrencyTick = value =>
    Number(value || 0).toLocaleString('th-TH', {
      maximumFractionDigits: 0,
    })

  const formatTooltip = value =>
    Number(value || 0).toLocaleString('th-TH', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })

  const formatShortCurrency = value =>
    `฿${Number(value || 0).toLocaleString('th-TH', {
      maximumFractionDigits: 0,
    })}`

  const thisYear = new Date().getFullYear()

  const monthlyOverviewData = useMemo(() => {
    const monthsName = [
      '',
      'ม.ค.',
      'ก.พ.',
      'มี.ค.',
      'เม.ย.',
      'พ.ค.',
      'มิ.ย.',
      'ก.ค.',
      'ส.ค.',
      'ก.ย.',
      'ต.ค.',
      'พ.ย.',
      'ธ.ค.',
    ]
    const filtered = (monthlyHistory || []).filter(
      item => Number(item.year) === thisYear
    )
    if (!filtered.length) return []
    return filtered
      .slice()
      .sort((a, b) => Number(a.month) - Number(b.month))
      .map(item => ({
        label: monthsName[item.month] || `เดือน ${item.month}`,
        value: Number(item.amount || 0),
      }))
  }, [monthlyHistory, thisYear])

  const yearlyOverviewData = useMemo(() => {
    const filtered = yearlyHistory || []
    if (!filtered.length) return []
    return filtered
      .slice()
      .sort((a, b) => Number(a.year) - Number(b.year))
      .map(item => ({
        label: String(item.year),
        value: Number(item.amount || 0),
      }))
  }, [yearlyHistory])

  const overviewChartData = useMemo(() => {
    if (overviewMode === 'all' && yearlyOverviewData.length) {
      return yearlyOverviewData
    }
    if (overviewMode === 'year' && monthlyOverviewData.length) {
      return monthlyOverviewData
    }
    return salesChartData || []
  }, [overviewMode, yearlyOverviewData, monthlyOverviewData, salesChartData])

  const isUsingHistoryData =
    (overviewMode === 'all' && yearlyOverviewData.length) ||
    (overviewMode === 'year' && monthlyOverviewData.length)

  return (
    <main className="flex-1 bg-slate-50/60">
      <div className="w-full px-6 py-6 lg:px-10 lg:py-10">
        <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-3xl font-semibold tracking-tight text-slate-900">
              แผงควบคุมร้านค้า
            </h1>
            <p className="mt-1 text-sm text-slate-500">
              ดูภาพรวมยอดขาย สต็อก และกิจกรรมล่าสุดของร้าน GOODTEA
            </p>
          </div>
          <div className="flex flex-wrap justify-end gap-3">
            <button className="inline-flex items-center rounded-full border border-slate-200 bg-white px-5 py-2.5 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50">
              วันนี้
            </button>
            <Link
              to="/"
              className="inline-flex items-center rounded-full bg-emerald-600 px-5 py-2.5 text-sm font-semibold text-white shadow-md hover:bg-emerald-700"
            >
              กลับไปหน้าร้าน
            </Link>
          </div>
        </div>

        {salesError && (
          <div className="mb-4 rounded-2xl border border-red-100 bg-red-50 px-4 py-3 text-sm text-red-600">
            {salesError}
          </div>
        )}

        <section className="mb-10 grid gap-4 md:grid-cols-3">
          {stats.map(item => (
            <div
              key={item.id}
              className="relative overflow-hidden rounded-2xl bg-white px-4 py-3 shadow-md ring-1 ring-slate-100"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-xs font-medium uppercase tracking-wide text-slate-400">
                    {item.title}
                  </p>
                  <p className="mt-2 text-2xl font-semibold text-slate-900">
                    {item.value}
                  </p>
                  {item.trendLabel && (
                    <div className="mt-2 flex items-center gap-2">
                      {item.trendValue && (
                        <span className="inline-flex items-center rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700">
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

        <section className="mb-10 grid gap-6 xl:grid-cols-3">
          <div className="xl:col-span-2 overflow-hidden rounded-3xl bg-gradient-to-br from-emerald-50 via-white to-sky-50 p-6 shadow-md ring-1 ring-emerald-100/60">
            <div className="mb-5 flex items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-semibold text-slate-900">
                  สรุปยอดขายทางการเงิน
                </h2>
                <p className="mt-1 text-xs text-slate-500">
                  ดูยอดขายแบบละเอียด แยกตามเดือนหรือปี
                </p>
              </div>
              <div className="inline-flex items-center rounded-full bg-white/90 p-1 text-xs shadow-sm ring-1 ring-emerald-100">
                <button
                  type="button"
                  onClick={() => setOverviewMode('year')}
                  className={`rounded-full px-3 py-1.5 font-medium ${overviewMode === 'year'
                    ? 'bg-emerald-600 text-white shadow-sm'
                    : 'text-emerald-700 hover:bg-emerald-50'
                    }`}
                >
                  ภาพรวมปีนี้
                </button>
                <button
                  type="button"
                  onClick={() => setOverviewMode('all')}
                  className={`rounded-full px-3 py-1.5 font-medium ${overviewMode === 'all'
                    ? 'bg-emerald-600 text-white shadow-sm'
                    : 'text-emerald-700 hover:bg-emerald-50'
                    }`}
                >
                  ภาพรวมทั้งหมด
                </button>
              </div>
            </div>

            <div className="mb-5 grid gap-3 text-xs text-slate-700 sm:grid-cols-3">
              {salesChartData.map(item => (
                <div
                  key={item.label}
                  className="flex items-center justify-between rounded-2xl bg-white/90 px-3.5 py-2.5 shadow-sm ring-1 ring-emerald-50"
                >
                  <div className="flex flex-col">
                    <span className="text-[11px] text-slate-400">
                      {item.label}
                    </span>
                    <span className="mt-1 text-sm font-semibold text-slate-900">
                      {formatShortCurrency(item.value)}
                    </span>
                  </div>
                  <span className="rounded-full bg-emerald-50 px-2.5 py-0.5 text-[10px] font-medium text-emerald-700">
                    ยอดรวม
                  </span>
                </div>
              ))}
            </div>

            <div className="h-72 rounded-3xl bg-white/90 px-3 py-3 shadow-sm ring-1 ring-emerald-50">
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
              {!salesLoading && !salesError && (!overviewChartData.length || !isUsingHistoryData) && (
                <div className="flex h-full items-center justify-center text-xs text-slate-400">
                  ยังไม่มีข้อมูลประวัติยอดขายสำหรับโหมดนี้
                </div>
              )}
              {!salesLoading &&
                !salesError &&
                overviewChartData.length > 0 &&
                (isUsingHistoryData || salesChartData.length > 0) && (
                  <ResponsiveContainer width="100%" aspect={2.5}>
                    <BarChart
                      data={overviewChartData}
                      margin={{ top: 8, right: 16, left: -20, bottom: 4 }}
                      barCategoryGap={40}
                    >
                      <defs>
                        <linearGradient
                          id="salesGradient"
                          x1="0"
                          y1="0"
                          x2="0"
                          y2="1"
                        >
                          <stop
                            offset="0%"
                            stopColor="#10b981"
                            stopOpacity={0.95}
                          />
                          <stop
                            offset="100%"
                            stopColor="#22c55e"
                            stopOpacity={0.75}
                          />
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
                          boxShadow: '0 10px 25px rgba(15, 23, 42, 0.08)',
                          fontSize: 12,
                        }}
                        formatter={value => [
                          `฿${formatTooltip(value)}`,
                          'ยอดขาย',
                        ]}
                      />
                      <Bar
                        dataKey="value"
                        radius={[12, 12, 6, 6]}
                        fill="url(#salesGradient)"
                      />
                    </BarChart>
                  </ResponsiveContainer>
                )}
            </div>
          </div>

          <div className="flex flex-col rounded-3xl bg-white p-6 shadow-md ring-1 ring-slate-100">
            <h2 className="mb-4 text-sm font-semibold text-slate-900">
              สินค้าขายดีวันนี้
            </h2>
            <div className="space-y-3">
              {products.length === 0 && (
                <p className="text-xs text-slate-400">
                  ยังไม่มีข้อมูลสินค้าขายดี
                </p>
              )}
              {products.map((product, index) => (
                <div
                  key={product.product_id || index}
                  className="flex items-center gap-4 rounded-2xl px-3 py-3 hover:bg-slate-50"
                >
                  <div className="h-16 w-16 flex-shrink-0 overflow-hidden rounded-xl bg-slate-100 ring-1 ring-slate-200">
                    <img
                      src={`/${product.image_url}`}
                      alt={product.name}
                      className="h-full w-full object-cover"
                    />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-slate-400">
                      อันดับ {index + 1}
                    </p>
                    <p className="truncate text-sm font-medium text-slate-900">
                      {product.name}
                    </p>
                    <p className="mt-1 text-xs font-semibold text-emerald-700">
                      ฿{product.total_revenue?.toLocaleString('th-TH', { maximumFractionDigits: 0 })} ขายได้ {product.total_sold} อัน
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="mb-10 grid gap-6 xl:grid-cols-2">
          <div className="rounded-3xl bg-white p-6 shadow-md ring-1 ring-slate-100">
            <h2 className="mb-4 text-sm font-semibold text-slate-900">
              สถานะคำสั่งซื้อ
            </h2>
            <div className="space-y-3">
              {orderStatusDistribution.length === 0 && (
                <p className="text-xs text-slate-400">
                  ยังไม่มีข้อมูลคำสั่งซื้อ
                </p>
              )}
              {orderStatusDistribution.map((item, index) => (
                <div
                  key={item.status}
                  className="flex items-center justify-between rounded-2xl px-3 py-2.5 hover:bg-slate-50"
                >
                  <div className="flex items-center gap-3">
                    <div className={`h-3 w-3 rounded-full ${item.status === 'completed' ? 'bg-emerald-500' :
                      item.status === 'paid' ? 'bg-blue-500' :
                        item.status === 'processing' ? 'bg-yellow-500' :
                          item.status === 'shipped' ? 'bg-purple-500' :
                            item.status === 'canceled' ? 'bg-red-500' :
                              'bg-gray-500'
                      }`} />
                    <span className="text-sm font-medium text-slate-900 capitalize">
                      {item.status === 'paid' ? 'ชำระแล้ว' :
                        item.status === 'processing' ? 'กำลังดำเนินการ' :
                          item.status === 'shipped' ? 'จัดส่งแล้ว' :
                            item.status === 'completed' ? 'เสร็จสิ้น' :
                              item.status === 'canceled' ? 'ยกเลิก' :
                                item.status === 'refunded' ? 'คืนเงิน' :
                                  item.status}
                    </span>
                  </div>
                  <span className="text-sm font-semibold text-slate-700">
                    {item.count}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-3xl bg-white p-6 shadow-md ring-1 ring-slate-100">
            <h2 className="mb-4 text-sm font-semibold text-slate-900">
              รายได้ตามหมวดหมู่
            </h2>
            <div className="space-y-3">
              {revenueByCategory.length === 0 && (
                <p className="text-xs text-slate-400">
                  ยังไม่มีข้อมูลรายได้
                </p>
              )}
              {revenueByCategory.slice(0, 5).map((item, index) => (
                <div
                  key={item.category_id}
                  className="flex items-center justify-between rounded-2xl px-3 py-2.5 hover:bg-slate-50"
                >
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-slate-900">
                      {item.category_name}
                    </p>
                    <p className="text-xs text-slate-400">
                      {item.order_count} คำสั่งซื้อ
                    </p>
                  </div>
                  <span className="text-sm font-semibold text-emerald-700">
                    ฿{item.revenue.toLocaleString('th-TH', { maximumFractionDigits: 0 })}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-3">
          <div className="xl:col-span-2 rounded-3xl bg-white p-6 shadow-md ring-1 ring-slate-100">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">
                กิจกรรมล่าสุด
              </h2>
              <button className="text-xs font-medium text-emerald-600 hover:text-emerald-700">
                ดูทั้งหมด
              </button>
            </div>
            <div className="space-y-3">
              {activities.length === 0 && (
                <p className="text-xs text-slate-400">
                  ยังไม่มีข้อมูลกิจกรรมล่าสุด
                </p>
              )}
              {activities.map((activity, index) => (
                <div
                  key={index}
                  className="flex items-start gap-3 rounded-2xl px-2.5 py-2.5 hover:bg-slate-50"
                >
                  <div
                    className={`mt-0.5 inline-flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold ${activity.type === 'order' ? 'bg-blue-100 text-blue-700' :
                      activity.type === 'user' ? 'bg-emerald-100 text-emerald-700' :
                        activity.type === 'review' ? 'bg-purple-100 text-purple-700' :
                          'bg-gray-100 text-gray-700'
                      }`}
                  >
                    {activity.type === 'order' ? '🛒' :
                      activity.type === 'user' ? '👤' :
                        activity.type === 'review' ? '⭐' :
                          '📝'}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-slate-900">
                      {activity.description}
                    </p>
                    {activity.amount && (
                      <p className="text-xs font-semibold text-emerald-700">
                        ฿{activity.amount.toLocaleString('th-TH', { maximumFractionDigits: 0 })}
                      </p>
                    )}
                  </div>
                  <p className="whitespace-nowrap text-xs text-slate-400">
                    {new Date(activity.time).toLocaleDateString('th-TH', {
                      day: 'numeric',
                      month: 'short',
                      hour: '2-digit',
                      minute: '2-digit'
                    })}
                  </p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-3xl bg-white p-6 shadow-md ring-1 ring-slate-100">
            <h2 className="mb-4 text-sm font-semibold text-slate-900">
              ภาพรวมผู้ใช้งาน
            </h2>
            <div className="space-y-4 text-sm text-slate-700">
              <div className="flex items-center justify-between">
                <span>ผู้ใช้งานทั้งหมด</span>
                <span className="font-semibold">
                  {userStats
                    ? `${userStats.totalUsers.toLocaleString('th-TH')} คน`
                    : '-'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>ผู้ใช้ใหม่เดือนนี้</span>
                <span className="font-semibold text-emerald-700">
                  {userStats
                    ? `${userStats.newUsersThisMonth.toLocaleString(
                      'th-TH'
                    )} คน`
                    : '-'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>ผู้ใช้ใหม่เดือนที่แล้ว</span>
                <span className="font-semibold text-slate-700">
                  {userStats
                    ? `${userStats.newUsersLastMonth.toLocaleString(
                      'th-TH'
                    )} คน`
                    : '-'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>อัตราการเติบโต</span>
                <span
                  className={
                    userStats && userStats.growthPercentage > 0
                      ? 'font-semibold text-emerald-700'
                      : userStats && userStats.growthPercentage < 0
                        ? 'font-semibold text-rose-600'
                        : 'font-semibold text-slate-700'
                  }
                >
                  {userStats
                    ? `${userStats.growthPercentage.toFixed(1)}%`
                    : '-'}
                </span>
              </div>
              <div className="border-t border-slate-100 pt-3">
                <p className="text-xs text-slate-400">
                  ข้อมูลผู้ใช้งานจากระบบสมาชิกของ GOODTEA
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
