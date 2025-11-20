import React, { useState, useEffect } from 'react';
import { Link, useParams, useLocation } from 'react-router-dom';
import { productsData } from '../data/productsData';   // mock data
import { useShop } from '../context/ShopContext';

const ProductDetailpage = () => {
  const location = useLocation();
  const from = location.state?.from;

  const { id } = useParams();

  const [product, setProduct] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [qty, setQty] = useState(1);
  const [showPopup, setShowPopup] = useState(false);  // ✅ popup state

  const { addToCart, toggleFavorite, isFavorite } = useShop();

  useEffect(() => {
  const categoryIdToName = {
      4: 'ชาเขียว',
      5: 'ชาอู่หลง',
      6: 'ชาดำ',
      3: 'กาชงชา',
      8: 'ที่กรองชา',
      9: 'ถ้วยชา',
    };

    const fetchProduct = async () => {
      setLoading(true);

      try {
        const response = await fetch(`/api/v1/products/${id}`);

        if (!response.ok) {
          throw new Error('API responded with error');
        }

        const json = await response.json();
        const apiProduct = json.product;

        if (!apiProduct) {
          throw new Error('Product not found from API');
        }

        const categoryName = categoryIdToName[apiProduct.category_id] || 'อื่น ๆ';

        const img = apiProduct.image_url || '';

        const normalizedImg =
          img.startsWith('http')
            ? img
            : img.startsWith('/')
            ? img
            : `/${img}`;

        const mapped = {
          id: apiProduct.id,
          title: apiProduct.name,
          description: apiProduct.description,
          brand: '-',
          category: categoryName,
          quantity: apiProduct.stock,
          price: apiProduct.price,
          // ใช้แบบเดียวกับหน้า list: image_url.String ตรง ๆ
          coverImage: normalizedImg || '/images/default-product.jpg',
        };

        setProduct(mapped);
        setError(null);
      } catch (apiError) {
        console.warn('API fetch failed, using mock data...', apiError.message);

        const mockProduct = productsData.find(
          (item) => String(item.id) === String(id)
        );

        if (mockProduct) {
          setProduct(mockProduct);
          setError(null);
        } else {
          setError(apiError.message || 'ไม่สามารถโหลดข้อมูลสินค้าได้');
          setProduct(null);
        }
      } finally {
        setLoading(false);
      }
    };

    if (id) fetchProduct();
  }, [id]);

  const handleAddToCart = () => {
    if (!product) return;
    addToCart(product, qty);   
    setShowPopup(true);
    setTimeout(() => {
      setShowPopup(false);
    }, 3000); // popup แสดง 2 วิ
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-screen text-xl">
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col justify-center items-center min-h-screen">
        <div className="text-xl text-red-600 mb-4">Error: {error}</div>
        <Link
          to={from === 'favorites' ? '/favorites' : '/products'}
          className="text-blue-600 hover:underline"
        >
          {from === 'favorites'
            ? 'กลับไปหน้ารายการโปรด'
            : 'กลับไปหน้ารายการสินค้า'}
        </Link>
      </div>
    );
  }

  if (!product) {
    return (
      <div className="flex flex-col justify-center items-center min-h-screen">
        <div className="text-xl mb-4">Product not found</div>
        <Link
          to={from === 'favorites' ? '/favorites' : '/products'}
          className="text-blue-600 hover:underline"
        >
          {from === 'favorites'
            ? 'กลับไปหน้ารายการโปรด'
            : 'กลับไปหน้ารายการสินค้า'}
        </Link>
      </div>
    );
  }

  const favoriteActive = isFavorite(product.id);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-4">
        {from === 'favorites' ? (
          <Link
            to="/favorites"
            className="text-gray-600 hover:underline inline-block"
          >
            ← กลับไปหน้ารายการโปรด
          </Link>
        ) : (
          <Link
            to="/products"
            className="text-gray-600 hover:underline inline-block"
          >
            ← กลับไปหน้ารายการสินค้า
          </Link>
        )}
      </div>

      <div className="bg-white rounded-lg shadow-lg p-6">
        <h1 className="text-2xl font-semibold mb-4">{product.title}</h1>

        <div className="flex gap-8">
          {/* รูปสินค้า */}
          <div className="flex-shrink-0">
            <img
              src={product.coverImage}
              alt={product.title}
              className="max-w-xs rounded-lg object-cover"
            />
          </div>

          {/* ข้อมูลด้านขวาของรูป */}
          <div className="flex-1 space-y-6 ml-10">
            <div className="space-y-4">
              <p><span className="font-semibold"></span> {product.description}</p>
              <p><span className="font-semibold">Brand:</span> {product.brand}</p>
              <p><span className="font-semibold">Category:</span> {product.category}</p>
              <p><span className="font-semibold">Quantity:</span> {product.quantity}g.</p>
              <p><span className="font-semibold">Price:</span> {product.price} ฿</p>
            </div>

            {/*  ส่วนจำนวน + ปุ่ม อยู่ใต้รายละเอียดทั้งหมด */}
            <div className="mt-6 space-y-7">
              <div className="flex items-center gap-3">
                <span className="font-semibold">จำนวน :</span>
                <div className="inline-flex items-center border border-gray-300">
                  <button
                    type="button"
                    onClick={() => setQty(prev => (prev > 1 ? prev - 1 : 1))}
                    className="px-3 py-1 text-lg border-r border-gray-300 hover:bg-gray-100"
                  >
                    −
                  </button>

                  <span className="px-4 py-1 text-lg min-w-[3rem] text-center">
                    {qty}
                  </span>

                  <button
                    type="button"
                    onClick={() => setQty(prev => prev + 1)}
                    className="px-3 py-1 text-lg border-l border-gray-300 hover:bg-gray-100"
                  >
                    +
                  </button>
                </div>
              </div>

              {/* ปุ่มเพิ่มในรถเข็น + หัวใจ */}
              <div className="pt-4 border-t border-gray-200 mt-4 max-w-lg">
                <div className="flex items-center gap-4">
                  <button
                    className="bg-green-600 hover:bg-green-700 rounded-lg text-white px-20 py-3 text-center font-semibold transition"
                    onClick={handleAddToCart}
                  >
                    เพิ่มลงตะกร้า
                  </button>

                  <button
                    className={
                      `w-11 h-11 flex items-center justify-center rounded-full border transition
                      ${favoriteActive
                        ? 'bg-red-500 border-red-500 text-white'
                        : 'border-gray-300 hover:bg-gray-100 text-gray-500'}`
                    }
                    onClick={() => toggleFavorite(product)}
                  >
                    <span className="text-xl">
                      {favoriteActive ? '♥' : '♡'}
                    </span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Popup */}
      {showPopup && (
        <div className="fixed top-16 right-5 z-50">
          <div className="bg-green-400 text-white px-4 py-3 rounded-lg shadow-lg text-sm">
            เพิ่ม {product.title} จำนวน {qty} ชิ้น ลงในตะกร้าแล้ว
          </div>
        </div>
      )}
    </div>
  );
};

export default ProductDetailpage;