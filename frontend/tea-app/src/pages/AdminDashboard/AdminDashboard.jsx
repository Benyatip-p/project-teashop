// src/pages/AdminDashboard/AdminDashboard.jsx
import React, { useEffect, useState } from 'react'
import {
  ChartBarIcon,
} from '@heroicons/react/outline'
import AdminLayout from '../../components/AdminLayout'
import DashboardContent from './DashboardContent'
import {
  getDailySales,
  getMonthlySales,
  getYearlySales,
} from '../../api/dashboard/sales'

const formatCurrency = (amount) =>
  `฿${Number(amount || 0).toLocaleString('th-TH', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`

export default function AdminDashboard() {
  const [sales, setSales] = useState({ daily: 0, monthly: 0, yearly: 0 })
  const [salesLoading, setSalesLoading] = useState(true)
  const [salesError, setSalesError] = useState('')

  useEffect(() => {
    let isMounted = true

    const loadSales = async () => {
      try {
        setSalesLoading(true)
        setSalesError('')

        const [daily, monthly, yearly] = await Promise.all([
          getDailySales(),
          getMonthlySales(),
          getYearlySales(),
        ])

        if (!isMounted) return
        setSales({ daily, monthly, yearly })
      } catch (err) {
        if (!isMounted) return
        setSalesError('โหลดข้อมูลยอดขายไม่สำเร็จ')
      } finally {
        if (!isMounted) return
        setSalesLoading(false)
      }
    }

    loadSales()
    return () => {
      isMounted = false
    }
  }, [])

  const stats = [
    {
      id: 'today-sales',
      title: 'ยอดขายวันนี้',
      value: formatCurrency(sales.daily),
      trendLabel: 'ยอดขายรวมวันนี้',
      trendValue: '',
      iconBg: 'bg-emerald-50',
      icon: <ChartBarIcon className="h-6 w-6 text-emerald-600" />,
    },
    {
      id: 'month-sales',
      title: 'ยอดขายเดือนนี้',
      value: formatCurrency(sales.monthly),
      trendLabel: 'ยอดขายรวมตั้งแต่ต้นเดือน',
      trendValue: '',
      iconBg: 'bg-sky-50',
      icon: <ChartBarIcon className="h-6 w-6 text-sky-600" />,
    },
    {
      id: 'year-sales',
      title: 'ยอดขายปีนี้',
      value: formatCurrency(sales.yearly),
      trendLabel: 'ยอดขายรวมตั้งแต่ต้นปี',
      trendValue: '',
      iconBg: 'bg-amber-50',
      icon: <ChartBarIcon className="h-6 w-6 text-amber-500" />,
    },
  ]

  const salesChartData = [
    { label: 'วันนี้', value: sales.daily },
    { label: 'เดือนนี้', value: sales.monthly },
    { label: 'ปีนี้', value: sales.yearly },
  ]

  const products = [
    { id: 1, img: '/assets/images/products/s1.jpg', name: 'ชาเขียวโฮจิฉะ', category: 'ชาเขียว', price: 120, sold: 48 },
    { id: 2, img: '/assets/images/products/s2.jpg', name: 'ชาไทยพรีเมียม', category: 'ชาไทย', price: 95, sold: 65 },
    { id: 3, img: '/assets/images/products/s3.jpg', name: 'โอวัลตินเย็น', category: 'เมนูอื่น ๆ', price: 80, sold: 34 },
    { id: 4, img: '/assets/images/products/s4.jpg', name: 'มัทฉะแฟรป', category: 'มัทฉะ', price: 140, sold: 51 },
  ]

  return (
    <AdminLayout title="แผงควบคุมร้านค้า (Dashboard)">
      <DashboardContent
        stats={stats}
        products={products}
        salesChartData={salesChartData}
        salesLoading={salesLoading}
        salesError={salesError}
      />
    </AdminLayout>
  )
}
