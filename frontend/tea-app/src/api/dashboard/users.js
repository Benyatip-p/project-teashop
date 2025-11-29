// src/api/dashboard/users.js
import api from '../api'

export const getUserStats = async () => {
  const { data } = await api.get('/admin/users/stats')

  return {
    totalUsers: data.total_users ?? 0,
    newUsersThisMonth: data.new_users_this_month ?? 0,
    newUsersLastMonth: data.new_users_last_month ?? 0,
    growthPercentage:
      typeof data.growth_percentage === 'number'
        ? data.growth_percentage
        : Number(data.growth_percentage || 0),
  }
}
