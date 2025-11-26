import React, { useState, useEffect } from 'react'
import { Link, useParams, useLocation } from 'react-router-dom'
import { productsData } from '../data/productsData'
import { useShop } from '../context/ShopContext'

const sizeOptions = [
  { size: '20g', stock: 5 },
  { size: '50g', stock: 8 },
  { size: '100g', stock: 3 },
]

const getMockDetails = category => {
  if (category === 'ชาเขียว') {
    return {
      origin:
        'แหล่งปลูกโซนอุจิ จังหวัดเกียวโต ประเทศญี่ปุ่น ปลูกบนพื้นที่สูง อากาศเย็นตลอดปี',
      process:
        'เก็บใบอ่อนช่วงเช้าแล้วนำไปนึ่งหยุดการออกซิไดซ์แบบ Sencha ทำให้ได้กลิ่นหอมสดและสีชาใส',
      highlight:
        'รสหวานนุ่ม ดื่มง่าย เหมาะกับการดื่มตอนเช้าหรือบ่ายเบา ๆ',
      mood:
        'กลิ่นหญ้าอ่อน ดอกไม้ขาว สาหร่ายทะเลบาง ๆ และปลายหวานแบบน้ำผึ้ง',
      caffeine: 'ปานกลาง',
    }
  }
  if (category === 'ชาดำ') {
    return {
      origin: 'ใบชาจากโซนยูนนานและอัสสัม คัดเฉพาะใบกลางถึงใบอ่อน',
      process:
        'ออกซิไดซ์เต็มที่แล้วอบด้วยอุณหภูมิต่ำให้กลิ่นหอมคาราเมลและมอลต์เด่นขึ้น',
      highlight:
        'บอดี้แน่น กลิ่นชัด เหมาะสำหรับดื่มกับนม หรือดื่มเดี่ยวก็ยังบาลานซ์ดี',
      mood: 'โน้ตมอลต์ คาราเมล น้ำตาลทรายแดง และผลไม้อบแห้งเล็กน้อย',
      caffeine: 'ค่อนข้างสูง',
    }
  }
  if (category === 'ชาอู่หลง') {
    return {
      origin: 'ชาจากโซนภูเขาสูงไต้หวัน คัดเฉพาะยอดและสองใบถัดมา',
      process:
        'ออกซิไดซ์บางส่วนแล้วคั่วอ่อน ทำให้ได้ความหอมแบบดอกไม้และถั่ว',
      highlight:
        'นุ่ม ลื่นคอ มีกลิ่นหอมหวานติดจมูก เหมาะสำหรับจิบช้า ๆ ระหว่างวัน',
      mood: 'กลิ่นดอกไม้ขาว น้ำผึ้งดอกส้ม และถั่วอัลมอนด์คั่วอ่อน',
      caffeine: 'ปานกลางถึงต่ำ',
    }
  }
  if (category === 'กาชงชา') {
    return {
      origin:
        'ออกแบบในสตูดิโอเล็ก ๆ ของ GOODTEA และผลิตจากโรงงานเซรามิกคุณภาพสูง',
      process:
        'ดินเซรามิกเผาอุณหภูมิสูง เคลือบให้ทนความร้อนและทำความสะอาดง่าย',
      highlight:
        'ทรงจับถนัดมือ เทน้ำชาได้ต่อเนื่องไม่หกเลอะ เหมาะกับทั้งชาร้อนและชาเย็น',
      mood: 'โทนอบอุ่น เรียบง่าย มินิมอล เข้ากับทุกโต๊ะชา',
      caffeine: '- (ไม่มีคาเฟอีน เป็นอุปกรณ์ชงชา)',
    }
  }
  if (category === 'ที่กรองชา') {
    return {
      origin: 'สแตนเลสเกรด food-safe ผลิตจากโรงงานที่ได้มาตรฐาน',
      process:
        'ขึ้นรูปด้วยแม่พิมพ์ละเอียด ตาข่ายถี่ไม่ให้กากชาหลุดออกมา',
      highlight: 'น้ำชาใส สะอาด ใช้ได้ทั้งกับแก้วและกาชงหลายขนาด',
      mood: 'ใช้งานง่าย เรียบแต่ดูโปรเฟสชันนัล',
      caffeine: '- (ไม่มีคาเฟอีน เป็นอุปกรณ์ชงชา)',
    }
  }
  if (category === 'ถ้วยชา') {
    return {
      origin: 'ออกแบบให้รับกับอุ้งมือขณะถือ ดินเซรามิกเผาอุณหภูมิสูง',
      process:
        'ขึ้นรูปด้วยมือแล้วจึงเข้าเตาเผา เคลือบด้านให้สัมผัสนุ่ม',
      highlight:
        'ริมปากถ้วยบางพอดี จิบแล้วรู้สึกชาไหลลื่น ไม่หนักปาก',
      mood: 'ให้ฟีลอบอุ่น เรียบง่าย เหมาะกับทุกแนวชาที่คุณชอบ',
      caffeine: '- (ไม่มีคาเฟอีน เป็นอุปกรณ์เสิร์ฟชา)',
    }
  }
  return {
    origin:
      'เลือกใช้วัตถุดิบและแหล่งผลิตที่มีมาตรฐานจากผู้ผลิตที่ไว้ใจได้',
    process: 'ผ่านขั้นตอนการคัดสรรและผลิตอย่างใส่ใจในทุกดีเทล',
    highlight:
      'ออกแบบมาให้ใช้งานง่ายและเข้ากับไลฟ์สไตล์การดื่มชาสมัยใหม่',
    mood: 'โทนสะอาด มินิมอล ใช้งานได้ในทุกวัน',
    caffeine: 'ขึ้นอยู่กับชนิดชาที่ใช้',
  }
}

const ProductDetailpage = () => {
  const location = useLocation()
  const from = location.state?.from
  const { id } = useParams()

  const [product, setProduct] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [qty, setQty] = useState(1)
  const [showPopup, setShowPopup] = useState(false)
  const [selectedSize, setSelectedSize] = useState('100g')

  const { addToCart, toggleFavorite, isFavorite } = useShop()

  useEffect(() => {
    const categoryIdToName = {
      4: 'ชาเขียว',
      5: 'ชาอู่หลง',
      6: 'ชาดำ',
      3: 'กาชงชา',
      8: 'ที่กรองชา',
      9: 'ถ้วยชา',
    }

    const fetchProduct = async () => {
      setLoading(true)
      try {
        const response = await fetch(`/api/v1/products/${id}`)
        if (!response.ok) throw new Error('API responded with error')

        const json = await response.json()
        const apiProduct = json.product
        if (!apiProduct) throw new Error('Product not found from API')

        const categoryName =
          categoryIdToName[apiProduct.category_id] || 'อื่น ๆ'

        const img = apiProduct.image_url || ''
        const normalizedImg =
          img.startsWith('http') ? img : img.startsWith('/') ? img : `/${img}`

        const mapped = {
          id: apiProduct.id,
          title: apiProduct.name,
          description: apiProduct.description,
          category: categoryName,
          price: apiProduct.price,
          coverImage: normalizedImg || '/images/default-product.jpg',
        }

        setProduct(mapped)
        setError(null)
      } catch {
        const mockProduct = productsData.find(
          item => String(item.id) === String(id),
        )

        if (mockProduct) {
          setProduct(mockProduct)
          setError(null)
        } else {
          setError('ไม่สามารถโหลดข้อมูลสินค้าได้')
          setProduct(null)
        }
      } finally {
        setLoading(false)
      }
    }

    if (id) fetchProduct()
  }, [id])

  const handleAddToCart = () => {
    if (!product) return
    addToCart({ ...product, selectedSize }, qty)
    setShowPopup(true)
    setTimeout(() => setShowPopup(false), 3000)
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        Loading...
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center">
        <p className="mb-4 text-red-500">{error}</p>
        <Link
          to={from === 'favorites' ? '/favorites' : '/products'}
          className="text-green-700 hover:underline"
        >
          ← กลับไปหน้ารายการสินค้า
        </Link>
      </div>
    )
  }

  if (!product) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center">
        <p className="mb-4">ไม่พบสินค้า</p>
        <Link
          to={from === 'favorites' ? '/favorites' : '/products'}
          className="text-green-700 hover:underline"
        >
          ← กลับไปหน้ารายการสินค้า
        </Link>
      </div>
    )
  }

  const favoriteActive = isFavorite(product.id)
  const details = getMockDetails(product.category)
  const selectedSizeData = sizeOptions.find(s => s.size === selectedSize)

  return (
    <div className="min-h-[calc(100vh-72px)] bg-[#f5f7f5]">
      <div className="mx-auto max-w-6xl px-6 py-10">
        <Link
          to={from === 'favorites' ? '/favorites' : '/products'}
          className="text-sm text-gray-500 hover:text-gray-700"
        >
          ← กลับไปหน้ารายการสินค้า
        </Link>

        <section className="mt-6 grid gap-10 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1.3fr)] items-start">
          <div className="space-y-6">
            <div className="overflow-hidden rounded-2xl bg-white shadow">
              <img
                src={product.coverImage}
                alt={product.title}
                className="aspect-[4/3] w-full object-cover"
              />
            </div>
          </div>

          <div className="flex flex-col gap-8">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-emerald-800">
                GOODTEA SELECTION
              </p>
              <h1 className="mt-1 text-3xl font-semibold text-gray-900">
                {product.title}
              </h1>
              <p className="mt-1 text-sm font-medium text-emerald-900">
                {product.category}
              </p>
              {product.description && (
                <p className="mt-3 max-w-xl text-sm leading-relaxed text-gray-700">
                  {product.description}
                </p>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-3 text-sm text-gray-700">
              <span className="inline-flex items-center rounded-full bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-800">
                คาเฟอีน: {details.caffeine}
              </span>
              <span className="text-2xl font-semibold text-gray-900">
                ฿{product.price}
              </span>
            </div>

            <div className="space-y-4 border-t border-gray-200 pt-5">
              <div>
                <p className="text-sm font-medium text-gray-800">เลือกขนาด</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {sizeOptions.map(item => (
                    <button
                      key={item.size}
                      type="button"
                      onClick={() => setSelectedSize(item.size)}
                      className={`rounded-full border px-4 py-2 text-sm ${
                        selectedSize === item.size
                          ? 'border-[#0b2f27] bg-[#0b2f27] text-white'
                          : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
                      }`}
                    >
                      {item.size}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium text-gray-800">
                    จำนวน
                  </span>
                  <div className="flex items-center rounded-lg border border-gray-300">
                    <button
                      type="button"
                      onClick={() => setQty(q => Math.max(1, q - 1))}
                      className="flex h-9 w-9 items-center justify-center border-r text-lg"
                    >
                      −
                    </button>
                    <span className="w-10 text-center text-sm font-semibold">
                      {qty}
                    </span>
                    <button
                      type="button"
                      onClick={() => setQty(q => q + 1)}
                      className="flex h-9 w-9 items-center justify-center border-l text-lg"
                    >
                      +
                    </button>
                  </div>
                </div>

                {selectedSizeData && (
                  <span className="text-xs text-gray-500">
                    สินค้าคงเหลือประมาณ {selectedSizeData.stock} ชิ้นสำหรับขนาดนี้
                  </span>
                )}
              </div>

              <div className="flex items-center gap-4 pt-2">
                <button
                  type="button"
                  onClick={handleAddToCart}
                  className="flex-1 rounded-xl bg-[#0b2f27] py-3 font-semibold text-white transition-colors hover:bg-[#13493d]"
                >
                  เพิ่มลงตะกร้า
                </button>
                <button
                  type="button"
                  onClick={() => toggleFavorite(product)}
                  className={`flex h-11 w-11 items-center justify-center rounded-full border transition ${
                    favoriteActive
                      ? 'border-red-500 bg-red-500 text-white'
                      : 'border-gray-300 text-gray-500 hover:bg-gray-50'
                  }`}
                >
                  <span className="text-xl">
                    {favoriteActive ? '♥' : '♡'}
                  </span>
                </button>
              </div>
            </div>
          </div>
        </section>

        <section className="mt-10 rounded-3xl bg-white px-8 py-7 shadow-sm">
          <p className="text-sm font-semibold text-gray-900">
            รายละเอียดสินค้าที่ลึกขึ้น
          </p>
          <div className="mt-4 grid gap-6 md:grid-cols-2">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-500">
                แหล่งปลูก / ที่มา
              </p>
              <p className="mt-1 text-sm leading-relaxed text-gray-800">
                {details.origin}
              </p>
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-500">
                วิธีการผลิตพิเศษ
              </p>
              <p className="mt-1 text-sm leading-relaxed text-gray-800">
                {details.process}
              </p>
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-500">
                จุดเด่นของชา
              </p>
              <p className="mt-1 text-sm leading-relaxed text-gray-800">
                {details.highlight}
              </p>
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-500">
                Mood &amp; Flavor Notes
              </p>
              <p className="mt-1 text-sm leading-relaxed text-gray-800">
                {details.mood}
              </p>
            </div>
          </div>
        </section>

        {showPopup && (
          <div className="fixed right-5 top-16 z-50">
            <div className="rounded-xl bg-emerald-500 px-5 py-3 text-sm text-white shadow-lg">
              เพิ่ม {product.title} ({selectedSize}) จำนวน {qty} ชิ้น ลงในตะกร้าแล้ว
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ProductDetailpage
