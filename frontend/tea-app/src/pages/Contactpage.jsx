import React, { useState } from 'react'
import {
  MailIcon,
  PhoneIcon,
  LocationMarkerIcon,
  ClockIcon,
} from '@heroicons/react/outline'

const ContactPage = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    subject: '',
    message: '',
  })

  const [submitted, setSubmitted] = useState(false)

  const handleChange = e => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value,
    }))
  }

  const handleSubmit = e => {
    e.preventDefault()
    console.log('Form submitted:', formData)
    setSubmitted(true)
    setTimeout(() => {
      setSubmitted(false)
      setFormData({
        name: '',
        email: '',
        phone: '',
        subject: '',
        message: '',
      })
    }, 3000)
  }

  return (
    <div className="min-h-screen bg-gray-50 py-12">
      <div className="container mx-auto px-4">
        <div className="mx-auto max-w-6xl">
          <div className="mb-12 text-center">
            <h1 className="mb-4 text-4xl font-bold text-gray-900">ติดต่อเรา</h1>
            <p className="text-lg text-gray-600">
              มีคำถาม ต้องการความช่วยเหลือ หรืออยากพูดคุยเกี่ยวกับชา เรายินดีรับฟังเสมอ
            </p>
          </div>

          <div className="grid gap-8 lg:grid-cols-3">
            <div className="lg:col-span-1">
              <div className="rounded-2xl bg-white p-8 shadow-lg">
                <h2 className="mb-6 text-2xl font-bold text-gray-900">
                  ข้อมูลการติดต่อ
                </h2>

                <div className="space-y-6 text-sm text-gray-700">
                  <div className="flex items-start">
                    <LocationMarkerIcon className="mr-4 mt-1 h-6 w-6 flex-shrink-0 text-viridian-700" />
                    <div>
                      <h3 className="mb-1 font-semibold text-gray-900">ที่อยู่</h3>
                      <p className="leading-relaxed text-gray-600">
                        123 ถนนชงชา แขวงชาดี
                        <br />
                        เขตชงดี กรุงเทพฯ 10200
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start">
                    <PhoneIcon className="mr-4 mt-1 h-6 w-6 flex-shrink-0 text-viridian-700" />
                    <div>
                      <h3 className="mb-1 font-semibold text-gray-900">โทรศัพท์</h3>
                      <p className="text-gray-600">02-123-4567</p>
                      <p className="text-gray-600">086-123-4567</p>
                    </div>
                  </div>

                  <div className="flex items-start">
                    <MailIcon className="mr-4 mt-1 h-6 w-6 flex-shrink-0 text-viridian-700" />
                    <div>
                      <h3 className="mb-1 font-semibold text-gray-900">อีเมล</h3>
                      <p className="text-gray-600">info@goodtea.co.th</p>
                      <p className="text-gray-600">support@goodtea.co.th</p>
                    </div>
                  </div>

                  <div className="flex items-start">
                    <ClockIcon className="mr-4 mt-1 h-6 w-6 flex-shrink-0 text-viridian-700" />
                    <div>
                      <h3 className="mb-1 font-semibold text-gray-900">
                        เวลาทำการ
                      </h3>
                      <p className="text-gray-600">จันทร์ - ศุกร์: 9:00 - 18:00</p>
                      <p className="text-gray-600">เสาร์: 10:00 - 16:00</p>
                      <p className="text-gray-600">อาทิตย์: ปิดทำการ</p>
                    </div>
                  </div>
                </div>

                <div className="mt-10 border-t border-gray-200 pt-8">
                  <h3 className="mb-4 font-semibold text-gray-900">ติดตามเรา</h3>
                  <div className="flex space-x-4">
                    <button
                      type="button"
                      className="rounded-full bg-emerald-50/20 p-2 text-viridian-700 shadow-sm transition hover:bg-emerald-100/40"
                    >
                      <svg
                        className="h-6 w-6"
                        fill="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path d="M22.675 0h-21.35C.597 0 0 .598 0 1.333v21.333C0 23.403.597 24 1.325 24h11.495v-9.333H9.692v-3.667h3.128V8.667c0-3.1 1.894-4.788 4.66-4.788 1.325 0 2.464.098 2.796.142v3.24h-1.918c-1.504 0-1.795.715-1.795 1.763v2.313h3.587l-.467 3.667h-3.12V24h6.116C23.403 24 24 23.403 24 22.667V1.333C24 .598 23.403 0 22.675 0z" />
                      </svg>
                    </button>

                    <button
                      type="button"
                      className="rounded-full bg-emerald-50/20 p-2 text-viridian-700 shadow-sm transition hover:bg-emerald-100/40"
                    >
                      <svg
                        className="h-6 w-6"
                        fill="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067A13.995 13.995 0 007.557 22.77C16.61 22.77 21.555 15.27 21.555 8.282c0-.21-.01-.42-.015-.63A9.935 9.935 0 0024 4.59z" />
                      </svg>
                    </button>

                    <button
                      type="button"
                      className="rounded-full bg-emerald-50/20 p-2 text-viridian-700 shadow-sm transition hover:bg-emerald-100/40"
                    >
                      <svg
                        className="h-6 w-6"
                        fill="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zM5.838 12a6.162 6.162 0 1112.324 0 6.162 6.162 0 01-12.324 0z" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="lg:col-span-2">
              <div className="rounded-2xl bg-white p-8 shadow-lg">
                <h2 className="mb-6 text-2xl font-bold text-gray-900">
                  ส่งข้อความถึงเรา
                </h2>

                {submitted ? (
                  <div className="rounded-lg border border-green-400 bg-green-50 px-4 py-3 text-sm text-green-800">
                    ขอบคุณที่ติดต่อเรา เราจะตอบกลับคุณโดยเร็วที่สุด
                  </div>
                ) : (
                  <form onSubmit={handleSubmit} className="space-y-6">
                    <div className="grid gap-6 md:grid-cols-2">
                      <div>
                        <label
                          htmlFor="name"
                          className="mb-2 block text-sm font-medium text-gray-700"
                        >
                          ชื่อ-นามสกุล *
                        </label>
                        <input
                          type="text"
                          id="name"
                          name="name"
                          value={formData.name}
                          onChange={handleChange}
                          required
                          className="w-full rounded-lg border border-gray-300 px-4 py-2 text-sm focus:border-transparent focus:ring-2 focus:ring-viridian-600"
                        />
                      </div>

                      <div>
                        <label
                          htmlFor="email"
                          className="mb-2 block text-sm font-medium text-gray-700"
                        >
                          อีเมล *
                        </label>
                        <input
                          type="email"
                          id="email"
                          name="email"
                          value={formData.email}
                          onChange={handleChange}
                          required
                          className="w-full rounded-lg border border-gray-300 px-4 py-2 text-sm focus:border-transparent focus:ring-2 focus:ring-viridian-600"
                        />
                      </div>
                    </div>

                    <div className="grid gap-6 md:grid-cols-2">
                      <div>
                        <label
                          htmlFor="phone"
                          className="mb-2 block text-sm font-medium text-gray-700"
                        >
                          เบอร์โทรศัพท์
                        </label>
                        <input
                          type="tel"
                          id="phone"
                          name="phone"
                          value={formData.phone}
                          onChange={handleChange}
                          className="w-full rounded-lg border border-gray-300 px-4 py-2 text-sm focus:border-transparent focus:ring-2 focus:ring-viridian-600"
                        />
                      </div>

                      <div>
                        <label
                          htmlFor="subject"
                          className="mb-2 block text-sm font-medium text-gray-700"
                        >
                          หัวข้อ *
                        </label>
                        <select
                          id="subject"
                          name="subject"
                          value={formData.subject}
                          onChange={handleChange}
                          required
                          className="w-full rounded-lg border border-gray-300 px-4 py-2 text-sm focus:border-transparent focus:ring-2 focus:ring-viridian-600"
                        >
                          <option value="">เลือกหัวข้อ</option>
                          <option value="general">สอบถามทั่วไป</option>
                          <option value="order">เกี่ยวกับคำสั่งซื้อ</option>
                          <option value="shipping">การจัดส่ง</option>
                          <option value="return">การคืนสินค้า</option>
                          <option value="complaint">ร้องเรียน</option>
                          <option value="suggestion">ข้อเสนอแนะ</option>
                        </select>
                      </div>
                    </div>

                    <div>
                      <label
                        htmlFor="message"
                        className="mb-2 block text-sm font-medium text-gray-700"
                      >
                        ข้อความ *
                      </label>
                      <textarea
                        id="message"
                        name="message"
                        rows={6}
                        value={formData.message}
                        onChange={handleChange}
                        required
                        className="w-full resize-none rounded-lg border border-gray-300 px-4 py-2 text-sm focus:border-transparent focus:ring-2 focus:ring-viridian-600"
                      />
                    </div>

                    <div className="flex justify-end">
                      <button
                        type="submit"
                        className="rounded-lg bg-viridian-800 px-8 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-viridian-900 hover:shadow-md"
                      >
                        ส่งข้อความ
                      </button>
                    </div>
                  </form>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ContactPage
