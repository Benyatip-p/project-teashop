// src/pages/AddBookPage.jsx
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { BookOpenIcon, LogoutIcon } from '@heroicons/react/outline';

const AddBookPage = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    title: '',
    author: '',
    isbn: '',
    year: '',
    price: '',
    category: '',
    original_price: '',
    discount: '',
    cover_image: '',
    cover_file: null,
    rating: '',
    reviews_count: '',
    is_new: false,
    pages: '',
    language: '',
    publisher: '',
    description: ''
  });
  const [coverPreview, setCoverPreview] = useState('');
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [categories, setCategories] = useState([]);

  // ตรวจสอบ Admin
  useEffect(() => {
    if (localStorage.getItem('isAdminAuthenticated') !== 'true') {
      navigate('/login');
    }
  }, [navigate]);

  // Fetch categories
  useEffect(() => {
    const fetchCategories = async () => {
      try {
        const res = await fetch('http://localhost:8080/api/v1/categories');
        if (!res.ok) throw new Error('โหลดหมวดหมู่ล้มเหลว');
        const data = await res.json();
        setCategories(data);
      } catch (error) {
        console.error(error);
      }
    };
    fetchCategories();
  }, []);

  const handleChange = (e) => {
    const { name, value, type, checked, files } = e.target;
    if (type === 'file') {
      const file = files[0];
      setFormData(prev => ({ ...prev, cover_file: file, cover_image: '' }));
      if (file) setCoverPreview(URL.createObjectURL(file));
    } else {
      setFormData(prev => ({ ...prev, [name]: type === 'checkbox' ? checked : value }));
      if (name === 'cover_image') setCoverPreview(value);
    }
    if (errors[name]) setErrors(prev => ({ ...prev, [name]: '' }));
  };

  const validateForm = () => {
    const newErrors = {};
    if (!formData.title.trim()) newErrors.title = 'กรุณากรอกชื่อหนังสือ';
    if (!formData.author.trim()) newErrors.author = 'กรุณากรอกชื่อผู้แต่ง';
    if (!formData.isbn.trim()) newErrors.isbn = 'กรุณากรอก ISBN';
    if (!formData.year || isNaN(parseInt(formData.year))) newErrors.year = 'กรุณากรอกปีที่ถูกต้อง';
    if (!formData.price || isNaN(parseFloat(formData.price))) newErrors.price = 'กรุณากรอกราคาที่ถูกต้อง';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSuccessMessage('');
    if (!validateForm()) return;
    setIsSubmitting(true);

    try {
      const payload = new FormData();
      for (const key in formData) {
        if (key === 'cover_image' && formData.cover_file) {
          payload.append('cover_image', formData.cover_file);
        } else if (key !== 'cover_file') {
          payload.append(key, formData[key]);
        }
      }

      const res = await fetch('http://localhost:8080/api/v1/books', {
        method: 'POST',
        body: payload
      });
      if (!res.ok) throw new Error('เพิ่มหนังสือล้มเหลว');
      const data = await res.json();
      setSuccessMessage(`เพิ่มหนังสือ "${data.title}" สำเร็จ!`);
      setFormData({
        title: '', author: '', isbn: '', year: '', price: '',
        category: '', original_price: '', discount: '', cover_image: '', cover_file: null,
        rating: '', reviews_count: '', is_new: false, pages: '',
        language: '', publisher: '', description: ''
      });
      setCoverPreview('');
      setTimeout(() => setSuccessMessage(''), 5000);
    } catch (error) {
      setErrors({ submit: error.message });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('isAdminAuthenticated');
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-gradient-to-r from-viridian-600 to-green-700 text-white shadow-lg">
        <div className="container mx-auto px-4 py-6 flex justify-between items-center">
          <div className="flex items-center space-x-3">
            <BookOpenIcon className="h-8 w-8" />
            <h1 className="text-2xl font-bold">BookStore - BackOffice</h1>
          </div>
          <button onClick={handleLogout} className="flex items-center space-x-2 px-4 py-2 bg-white/20 hover:bg-white/30 rounded-lg">
            <LogoutIcon className="h-5 w-5" />
            <span>ออกจากระบบ</span>
          </button>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        <div className="max-w-3xl mx-auto bg-white rounded-xl shadow-lg p-8">
          <h2 className="text-3xl font-bold mb-6">เพิ่มหนังสือใหม่</h2>

          {successMessage && <div className="mb-6 bg-green-50 border border-green-400 text-green-700 px-4 py-3 rounded-lg">{successMessage}</div>}
          {errors.submit && <div className="mb-6 bg-red-50 border border-red-400 text-red-700 px-4 py-3 rounded-lg">{errors.submit}</div>}

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* ฟิลด์หลัก */}
            {['title','author','isbn','year','price'].map(field => (
              <div key={field}>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  {field==='title'?'ชื่อหนังสือ':field==='author'?'ผู้แต่ง':field.toUpperCase()} <span className="text-red-500">*</span>
                </label>
                <input
                  type={field==='year' || field==='price' ? 'number':'text'}
                  name={field}
                  value={formData[field]}
                  onChange={handleChange}
                  className={`w-full px-4 py-3 border rounded-lg focus:outline-none focus:ring-2 ${errors[field]?'border-red-500 focus:ring-red-500':'border-gray-300 focus:ring-viridian-500'}`}
                />
                {errors[field] && <p className="mt-1 text-sm text-red-600">{errors[field]}</p>}
              </div>
            ))}

            {/* Category Dropdown */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">หมวดหมู่</label>
              <select
                name="category"
                value={formData.category}
                onChange={handleChange}
                className="w-full px-4 py-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-viridian-500"
              >
                <option value="">-- เลือกหมวดหมู่ --</option>
                {categories.map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
            </div>

            {/* Cover Image */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">รูปปกหนังสือ</label>
              <input type="text" placeholder="URL รูปปก" name="cover_image" value={formData.cover_image} onChange={handleChange} className="w-full px-4 py-3 border rounded-lg mb-2" />
              <p className="text-sm text-gray-500 mb-2">หรืออัปโหลดไฟล์จากเครื่อง</p>
              <input type="file" name="cover_image" accept="image/*" onChange={handleChange} className="w-full mb-4" />
              {coverPreview && (
                <img src={coverPreview} alt="Preview" className="w-48 h-64 object-cover rounded-lg border mb-4" />
              )}
            </div>

            {/* ฟิลด์อื่น ๆ */}
            <div className="grid grid-cols-2 gap-6">
              {['original_price','discount','rating','reviews_count','pages'].map(field => (
                <div key={field}>
                  <label className="block text-sm font-medium text-gray-700 mb-2">{field}</label>
                  <input type="number" name={field} value={formData[field]} onChange={handleChange} className="w-full px-4 py-3 border rounded-lg" step={field==='rating' || field==='original_price'? '0.1':'1'} />
                </div>
              ))}
            </div>
            {['language','publisher','description'].map(field => (
              <div key={field}>
                <label className="block text-sm font-medium text-gray-700 mb-2">{field}</label>
                {field==='description' ? (
                  <textarea name={field} value={formData[field]} onChange={handleChange} className="w-full px-4 py-3 border rounded-lg" rows={4} />
                ) : (
                  <input type="text" name={field} value={formData[field]} onChange={handleChange} className="w-full px-4 py-3 border rounded-lg" />
                )}
              </div>
            ))}

            <div className="flex items-center gap-4">
              <label className="inline-flex items-center">
                <input type="checkbox" name="is_new" checked={formData.is_new} onChange={handleChange} className="mr-2"/>
                <span>New Book</span>
              </label>
            </div>

            {/* Buttons */}
            <div className="flex gap-4">
              <button
                type="submit"
                disabled={isSubmitting}
                className={`flex-1 py-3 px-6 rounded-lg font-semibold text-white ${isSubmitting?'bg-gray-400':'bg-yellow-500 hover:bg-yellow-600'}`}
              >
                {isSubmitting ? 'กำลังบันทึก...' : 'เพิ่มหนังสือ'}
              </button>
              <button
                type="button"
                onClick={() => {navigate('/store-manager/dashboard'); window.scrollTo(0,0);}}
                className="px-6 py-3 border-2 border-gray-300 rounded-lg font-semibold text-gray-700 hover:bg-gray-50"
              >
                ยกเลิก
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default AddBookPage;
