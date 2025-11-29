// src/pages/AdminDashboard/AdminDashboard.jsx
import React, { useEffect, useState } from 'react'
import { ChartBarIcon } from '@heroicons/react/outline'
import AdminLayout from '../../components/AdminLayout'
import DashboardContent from './DashboardContent'
import {
  getDailySales,
  getMonthlySales,
  getYearlySales,
  getTopSellingProducts,
  getMonthlySalesHistory,
  getYearlySalesHistory,
} from '../../api/dashboard/sales'
import { getUserStats } from '../../api/dashboard/users'
import { getLowStockItems, getLowStockVariants } from '../../api/dashboard/inventory'

export default function AdminDashboard() {
  const [sales, setSales] = useState({ daily: 0, monthly: 0, yearly: 0 })
  const [products, setProducts] = useState([])
  const [userStats, setUserStats] = useState(null)
  const [monthlyHistory, setMonthlyHistory] = useState([])
  const [yearlyHistory, setYearlyHistory] = useState([])
  const [lowStockItems, setLowStockItems] = useState([])
  const [lowStockVariants, setLowStockVariants] = useState([])

  const [salesLoading, setSalesLoading] = useState(true)
  const [salesError, setSalesError] = useState('')

  useEffect(() => {
    let isMounted = true

    const load = async () => {
      try {
        setSalesLoading(true)
        setSalesError('')

        const [
          daily,
          monthly,
          yearly,
          topProducts,
          userStatsData,
          monthlyHist,
          yearlyHist,
          lowItems,
          lowVariants,
        ] = await Promise.all([
          getDailySales(),
          getMonthlySales(),
          getYearlySales(),
          getTopSellingProducts().catch(err => {
            console.error('getTopSellingProducts failed', err)
            return []
          }),
          getUserStats().catch(err => {
            console.error('getUserStats failed', err)
            return null
          }),
          getMonthlySalesHistory().catch(err => {
            console.error('getMonthlySalesHistory failed', err)
            return []
          }),
          getYearlySalesHistory().catch(err => {
            console.error('getYearlySalesHistory failed', err)
            return []
          }),
          getLowStockItems().catch(err => {
            console.error('getLowStockItems failed', err)
            return []
          }),
          getLowStockVariants().catch(err => {
            console.error('getLowStockVariants failed', err)
            return []
          }),
        ])

        if (!isMounted) return

        setSales({ daily, monthly, yearly })
        setProducts(topProducts || [])
        setUserStats(userStatsData)
        setMonthlyHistory(monthlyHist || [])
        setYearlyHistory(yearlyHist || [])
        setLowStockItems(lowItems || [])
        setLowStockVariants(lowVariants || [])
      } catch (err) {
        if (!isMounted) return
        console.error('Dashboard load failed', err)
        setSalesError('โหลดข้อมูลยอดขายไม่สำเร็จ')
      } finally {
        if (!isMounted) return
        setSalesLoading(false)
      }
    }

    load()
    return () => {
      isMounted = false
    }
  }, [])

  const stats = [
    {
      id: 'low-items',
      title: 'สินค้าใกล้หมด (ตามสินค้า)',
      value: `${lowStockItems.length} รายการ`,
      trendLabel: 'SKU ต่ำกว่าระดับเตือน',
      trendValue: '',
      iconBg: 'bg-rose-50',
      icon: <ChartBarIcon className="h-6 w-6 text-rose-500" />,
    },
    {
      id: 'low-variants',
      title: 'ตัวเลือกสินค้าใกล้หมด',
      value: `${lowStockVariants.length} ตัวเลือก`,
      trendLabel: 'Variant ใกล้หมดสต็อก',
      trendValue: '',
      iconBg: 'bg-amber-50',
      icon: <ChartBarIcon className="h-6 w-6 text-amber-500" />,
    },
    {
      id: 'low-total',
      title: 'รวมรายการที่ต้องเติมสต็อก',
      value: `${lowStockItems.length + lowStockVariants.length} รายการ`,
      trendLabel: 'ควรรีสต็อกเร็ว ๆ',
      trendValue: '',
      iconBg: 'bg-emerald-50',
      icon: <ChartBarIcon className="h-6 w-6 text-emerald-600" />,
    },
  ]

  const salesChartData = [
    { label: 'วันนี้', value: sales.daily },
    { label: 'เดือนนี้', value: sales.monthly },
    { label: 'ปีนี้', value: sales.yearly },
  ]

  return (
    <AdminLayout title="แผงควบคุมร้านค้า (Dashboard)">
      <DashboardContent
        stats={stats}
        products={products}
        salesChartData={salesChartData}
        salesLoading={salesLoading}
        salesError={salesError}
        userStats={userStats}
        monthlyHistory={monthlyHistory}
        yearlyHistory={yearlyHistory}
      />
    </AdminLayout>
  )
}
