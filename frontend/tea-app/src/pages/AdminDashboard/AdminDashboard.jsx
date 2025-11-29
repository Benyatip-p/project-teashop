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
  getOrderStatusDistribution,
  getAverageOrderValue,
  getTotalProductsCount,
  getRevenueByCategory,
  getRecentActivities,
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
  const [orderStatusDistribution, setOrderStatusDistribution] = useState([])
  const [averageOrderValue, setAverageOrderValue] = useState(0)
  const [totalProductsCount, setTotalProductsCount] = useState(0)
  const [revenueByCategory, setRevenueByCategory] = useState([])
  const [recentActivities, setRecentActivities] = useState([])

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
          orderStatusDist,
          avgOrderValue,
          totalProducts,
          revenueByCat,
          recentActivitiesData,
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
          getOrderStatusDistribution().catch(err => {
            console.error('getOrderStatusDistribution failed', err)
            return []
          }),
          getAverageOrderValue().catch(err => {
            console.error('getAverageOrderValue failed', err)
            return 0
          }),
          getTotalProductsCount().catch(err => {
            console.error('getTotalProductsCount failed', err)
            return 0
          }),
          getRevenueByCategory().catch(err => {
            console.error('getRevenueByCategory failed', err)
            return []
          }),
          getRecentActivities(15).catch(err => {
            console.error('getRecentActivities failed', err)
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
        setOrderStatusDistribution(orderStatusDist || [])
        setAverageOrderValue(avgOrderValue || 0)
        setTotalProductsCount(totalProducts || 0)
        setRevenueByCategory(revenueByCat || [])
        setRecentActivities(recentActivitiesData || [])
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
      value: `${lowStockVariants.length} รายการ`,
      trendLabel: 'ควรรีสต็อกเร็ว ๆ',
      trendValue: '',
      iconBg: 'bg-emerald-50',
      icon: <ChartBarIcon className="h-6 w-6 text-emerald-600" />,
    },
    {
      id: 'avg-order-value',
      title: 'มูลค่าคำสั่งซื้อเฉลี่ย',
      value: `฿${averageOrderValue.toLocaleString('th-TH', { maximumFractionDigits: 0 })}`,
      trendLabel: 'เฉลี่ยต่อคำสั่งซื้อ',
      trendValue: '',
      iconBg: 'bg-blue-50',
      icon: <ChartBarIcon className="h-6 w-6 text-blue-500" />,
    },
    {
      id: 'total-products',
      title: 'จำนวนสินค้าทั้งหมด',
      value: `${totalProductsCount} รายการ`,
      trendLabel: 'สินค้าที่ใช้งานได้',
      trendValue: '',
      iconBg: 'bg-purple-50',
      icon: <ChartBarIcon className="h-6 w-6 text-purple-500" />,
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
        orderStatusDistribution={orderStatusDistribution}
        averageOrderValue={averageOrderValue}
        totalProductsCount={totalProductsCount}
        revenueByCategory={revenueByCategory}
        recentActivities={recentActivities}
      />
    </AdminLayout>
  )
}
