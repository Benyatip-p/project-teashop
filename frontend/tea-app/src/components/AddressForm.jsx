import React, { useState, useEffect } from 'react';
import api from '../api/api';
import Select from 'react-select';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const AddressForm = () => {
  const [addresses, setAddresses] = useState([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [editingId, setEditingId] = useState(null);
  const [formData, setFormData] = useState({
    recipient_name: '',
    phone_number: '',
    address: '',
    province: '',
    district: '',
    subdistrict: '',
    postal_code: '',
    is_default: false
  });
  const [phoneError, setPhoneError] = useState('');
  const [provinces, setProvinces] = useState([]);

  // state สำหรับ popup ยืนยันลบ
  const [deletingId, setDeletingId] = useState(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  const MAX_ADDRESSES = 2;

  // โหลดข้อมูลจังหวัดจาก JSON file
  useEffect(() => {
    const fetchProvinces = async () => {
      try {
        const res = await fetch('/provinces.json');
        const data = await res.json();

        const formattedProvinces = data.map((p) => ({
          value: p.name,
          label: p.name,
        }));
        setProvinces(formattedProvinces);
      } catch (err) {
        console.error('โหลดจังหวัดไม่สำเร็จ:', err);
        toast.error('ไม่สามารถโหลดข้อมูลจังหวัดได้');
      }
    };
    fetchProvinces();
  }, []);

  // ฟังก์ชัน validate เบอร์โทรศัพท์
  const validatePhoneNumber = (phone) => {
    if (!/^\d+$/.test(phone)) {
      return 'กรุณากรอกเฉพาะตัวเลข 0-9 เท่านั้น';
    }
    
    if (phone.length < 9 || phone.length > 10) {
      return 'เบอร์โทรศัพท์ต้องมี 9-10 หลัก';
    }
    
    if (phone.length === 10 && !phone.startsWith('0')) {
      return 'เบอร์โทรศัพท์ 10 หลักต้องขึ้นต้นด้วย 0';
    }
    
    return '';
  };

  // Fetch addresses from API
  const fetchAddresses = async () => {
    try {
      setLoading(true);
      setError(null);
      
      console.log('Fetching addresses...');
      const response = await api.get('/addresses');
      console.log('Response:', response);
      
      const addressData = response.data.addresses || response.data.data || response.data;
      setAddresses(Array.isArray(addressData) ? addressData : []);
      
    } catch (error) {
      console.error('Failed to fetch addresses:', error);
      const errorMsg = error.response?.data?.error || 'ไม่สามารถโหลดข้อมูลที่อยู่ได้';
      setError(errorMsg);
      toast.error(errorMsg);
      setAddresses([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAddresses();
  }, []);

  // ฟังก์ชันแยกข้อมูลที่อยู่
  const parseAddress = (fullAddress) => {
    console.log('Parsing address:', fullAddress);
    
    let mainAddress = fullAddress;
    let subdistrict = '';
    let district = '';
    let postal_code = '';

    // 1. ดึงรหัสไปรษณีย์ออกก่อน (5 หลักท้ายสุด)
    const postalMatch = mainAddress.match(/\s*(\d{5})\s*$/);
    if (postalMatch) {
      postal_code = postalMatch[1];
      mainAddress = mainAddress.replace(postalMatch[0], '').trim();
    }

    // 2. ดึงจังหวัดออก (ถ้ามี)
    const provinceMatch = mainAddress.match(/จังหวัด([^\s,]+)/);
    if (provinceMatch) {
      mainAddress = mainAddress.replace(provinceMatch[0], '').trim();
    }

    // 3. ดึง "เขต/อำเภอ..." ออก
    const districtMatch = mainAddress.match(/(?:เขต|อำเภอ)([^\s,]+)/);
    if (districtMatch) {
      district = districtMatch[1].trim();
      mainAddress = mainAddress.replace(districtMatch[0], '').trim();
    }

    // 4. ดึง "แขวง/ตำบล..." ออก
    const subdistrictMatch = mainAddress.match(/(?:แขวง|ตำบล)([^\s,]+)/);
    if (subdistrictMatch) {
      subdistrict = subdistrictMatch[1].trim();
      mainAddress = mainAddress.replace(subdistrictMatch[0], '').trim();
    }

    // 5. ทำความสะอาดคอมม่าและช่องว่างที่เหลือ
    mainAddress = mainAddress
      .replace(/,+/g, ',')
      .replace(/^,|,$/g, '')
      .replace(/\s+/g, ' ')
      .trim();

    console.log('Parsed result:', {
      address: mainAddress,
      subdistrict,
      district,
      postal_code
    });

    return { 
      address: mainAddress, 
      subdistrict, 
      district,
      postal_code
    };
  };

  // ฟังก์ชันสำหรับเปิดฟอร์มแก้ไข
  const handleEdit = (addr) => {
    const parsed = parseAddress(addr.address);
    
    setFormData({
      recipient_name: addr.recipient_name || '',
      phone_number: addr.phone_number || '',
      address: parsed.address || '',
      province: addr.province || '',
      district: parsed.district || '',
      subdistrict: parsed.subdistrict || '',
      postal_code: addr.postal_code || parsed.postal_code || '',
      is_default: addr.is_default || false
    });
    
    setPhoneError('');
    setEditingId(addr.id);
    setShowAddForm(true);
  };

  // ฟังก์ชันแสดงที่อยู่ที่แยกส่วนแล้ว
  const formatDisplayAddress = (addr) => {
    console.log('Address from API:', addr);
    
    const parsed = parseAddress(addr.address);
    
    return (
      <div className="space-y-1">
        <p className="text-gray-600 text-sm leading-relaxed">
          {parsed.address}
        </p>
        
        <p className="text-gray-500 text-xs">
          {[
            parsed.subdistrict && `แขวง ${parsed.subdistrict}`,
            parsed.district && `เขต ${parsed.district}`,
            addr.province && `จังหวัด ${addr.province}`,
            addr.postal_code || parsed.postal_code
          ].filter(Boolean).join(', ')}
        </p>
      </div>
    );
  };

  // ฟังก์ชันเปิดฟอร์มเพิ่มที่อยู่ใหม่
  const handleAddNew = () => {
    if (addresses.length >= MAX_ADDRESSES) {
      toast.warning(`คุณสามารถเพิ่มที่อยู่ได้สูงสุด ${MAX_ADDRESSES} ที่อยู่เท่านั้น กรุณาลบที่อยู่เก่าก่อนเพิ่มใหม่`, {
        autoClose: 3000
      });
      return;
    }
    
    setEditingId(null);
    setPhoneError('');
    setFormData({
      recipient_name: '',
      phone_number: '',
      address: '',
      province: '',
      district: '',
      subdistrict: '',
      postal_code: '',
      is_default: false
    });
    setShowAddForm(true);
  };

  // Handle form input change
  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    
    if (name === 'phone_number') {
      const numericValue = value.replace(/[^0-9]/g, '');
      const limitedValue = numericValue.slice(0, 10);
      
      setFormData(prev => ({
        ...prev,
        [name]: limitedValue
      }));
      
      if (limitedValue.length > 0) {
        const error = validatePhoneNumber(limitedValue);
        setPhoneError(error);
      } else {
        setPhoneError('');
      }
    } else if (name === 'postal_code') {
      const numericValue = value.replace(/[^0-9]/g, '');
      const limitedValue = numericValue.slice(0, 5);
      
      setFormData(prev => ({
        ...prev,
        [name]: limitedValue
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        [name]: type === 'checkbox' ? checked : value
      }));
    }
  };

  // Handle province change
  const handleProvinceChange = (selectedOption) => {
    const provinceValue = selectedOption ? selectedOption.value : '';
    setFormData(prev => ({
      ...prev,
      province: provinceValue
    }));
  };

  // Handle form submit
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    const phoneValidationError = validatePhoneNumber(formData.phone_number);
    if (phoneValidationError) {
      setPhoneError(phoneValidationError);
      toast.error('กรุณาตรวจสอบเบอร์โทรศัพท์');
      return;
    }
    
    if (!editingId && addresses.length >= MAX_ADDRESSES) {
      toast.warning(`คุณสามารถเพิ่มที่อยู่ได้สูงสุด ${MAX_ADDRESSES} ที่อยู่เท่านั้น กรุณาลบที่อยู่เก่าก่อนเพิ่มใหม่`);
      return;
    }
    
    try {
      console.log('Submitting form data:', formData);
      
      const fullAddress = `${formData.address}, ตำบล${formData.subdistrict}, อำเภอ${formData.district}`;
      
      const submitData = {
        recipient_name: formData.recipient_name,
        phone_number: formData.phone_number,
        address: fullAddress,
        province: formData.province,
        postal_code: formData.postal_code,
        is_default: formData.is_default
      };
      
      console.log('Submit data:', submitData);
      
      if (editingId) {
        const response = await api.put(`/addresses/${editingId}`, submitData);
        console.log('Update response:', response);
        toast.success('แก้ไขที่อยู่สำเร็จ');
      } else {
        const response = await api.post('/addresses', submitData);
        console.log('Submit response:', response);
        toast.success('เพิ่มที่อยู่สำเร็จ');
      }
      
      handleCloseForm();
      fetchAddresses();
      
    } catch (error) {
      console.error('Failed to save address:', error);
      
      const errorMessage = error.response?.data?.error || error.response?.data?.message || 'ไม่สามารถบันทึกที่อยู่ได้';
      toast.error(errorMessage);
    }
  };

  // ฟังก์ชันปิดฟอร์มและรีเซ็ต
  const handleCloseForm = () => {
    setShowAddForm(false);
    setEditingId(null);
    setPhoneError('');
    setFormData({
      recipient_name: '',
      phone_number: '',
      address: '',
      province: '',
      district: '',
      subdistrict: '',
      postal_code: '',
      is_default: false
    });
  };

  // กดปุ่ม "ลบ" -> แค่เปิด popup ยืนยัน
  const handleDelete = (id) => {
    setDeletingId(id);
    setShowDeleteModal(true);
  };

  // กดปุ่ม "ยืนยัน" ใน popup -> ลบจริง
  const confirmDelete = async () => {
    if (!deletingId) return;

    try {
      await api.delete(`/addresses/${deletingId}`);
      toast.success('ลบที่อยู่สำเร็จ');
      fetchAddresses();
    } catch (error) {
      console.error('Failed to delete address:', error);
      const errorMsg = error.response?.data?.error || 'ไม่สามารถลบที่อยู่ได้';
      toast.error(errorMsg);
    } finally {
      setShowDeleteModal(false);
      setDeletingId(null);
    }
  };

  // Handle set as default
  const handleSetDefault = async (id) => {
    try {
      await api.put(`/addresses/${id}`, { is_default: true });
      toast.success('ตั้งเป็นที่อยู่เริ่มต้นสำเร็จ');
      fetchAddresses();
    } catch (error) {
      console.error('Failed to set default address:', error);
      const errorMsg = error.response?.data?.error || 'ไม่สามารถตั้งเป็นที่อยู่เริ่มต้นได้';
      toast.error(errorMsg);
    }
  };

  return (
    <>
      <ToastContainer 
        position="top-right"
        autoClose={3000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="light"
      />

      <div className="flex-1 bg-white p-6 shadow-sm rounded-lg min-h-[500px] max-w-none w-full">
        
        {/* Header Section */}
        <div className="flex justify-between items-center border-b border-gray-200 pb-4 mb-8">
          <div>
            <h1 className="text-xl font-medium text-gray-800">ที่อยู่ของฉัน</h1>
            <p className="text-sm text-gray-500 mt-1">
              จัดการที่อยู่สำหรับการจัดส่งสินค้า ({addresses.length}/{MAX_ADDRESSES} ที่อยู่)
            </p>
          </div>
          <button 
            onClick={handleAddNew}
            disabled={addresses.length >= MAX_ADDRESSES}
            className={`flex items-center gap-2 px-4 py-2 text-white font-medium text-sm rounded-xl transition-all shadow-lg ${
              addresses.length >= MAX_ADDRESSES 
                ? 'bg-gray-400 cursor-not-allowed opacity-60' 
                : 'bg-[#0b2f27] hover:bg-[#13493d] hover:shadow-xl transform hover:scale-105'
            }`}
            title={addresses.length >= MAX_ADDRESSES ? `สามารถเพิ่มได้สูงสุด ${MAX_ADDRESSES} ที่อยู่` : 'เพิ่มที่อยู่ใหม่'}
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            เพิ่มที่อยู่ใหม่
          </button>
        </div>

        {/* Warning when reaching limit */}
        {addresses.length >= MAX_ADDRESSES && (
          <div className="bg-amber-50 border border-amber-200 text-amber-800 px-4 py-3 rounded-xl mb-4 flex items-start gap-3">
            <svg className="w-5 h-5 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <div>
              <p className="text-sm font-medium">คุณได้เพิ่มที่อยู่ครบจำนวนสูงสุดแล้ว</p>
              <p className="text-xs mt-1">หากต้องการเพิ่มที่อยู่ใหม่ กรุณาลบที่อยู่เก่าก่อน</p>
            </div>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl mb-4 flex items-start gap-3">
            <svg className="w-5 h-5 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
            <p className="text-sm">{error}</p>
          </div>
        )}

        {/* Addresses List */}
        <div className="space-y-4">
          {loading ? (
            <div className="text-center py-16">
              <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-teal-600"></div>
              <p className="text-gray-500 mt-4">กำลังโหลดข้อมูล...</p>
            </div>
          ) : addresses.length > 0 ? (
            addresses.map((addr) => (
              <div 
                key={addr.id}
                className="bg-white border-2 border-gray-200 rounded-2xl p-6 hover:shadow-lg transition-all"
              >
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    {/* Name and Phone */}
                    <div className="flex items-center gap-3 mb-3">
                      <h3 className="text-lg font-semibold text-gray-800">
                        {addr.recipient_name}
                      </h3>
                      <span className="text-gray-400">|</span>
                      <span className="text-gray-600">{addr.phone_number}</span>
                      {addr.is_default && (
                        <span className="px-3 py-1 bg-red-100 text-red-600 text-xs font-medium rounded-lg border border-red-200">
                          ค่าเริ่มต้น
                        </span>
                      )}
                    </div>

                    {/* Address - แสดงที่อยู่แบบแยกส่วน */}
                    <div className="mb-4">
                      {formatDisplayAddress(addr)}
                    </div>

                    {/* Action Buttons */}
                    <div className="flex gap-3">
                      <button 
                        onClick={() => handleEdit(addr)}
                        className="text-teal-600 hover:text-teal-700 text-sm font-medium hover:underline transition-colors"
                      >
                        แก้ไข
                      </button>
                      {!addr.is_default && (
                        <>
                          <span className="text-gray-300">|</span>
                          <button 
                            onClick={() => handleDelete(addr.id)}
                            className="text-red-600 hover:text-red-700 text-sm font-medium hover:underline transition-colors"
                          >
                            ลบ
                          </button>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Set as Default Button */}
                  {!addr.is_default && (
                    <button 
                      onClick={() => handleSetDefault(addr.id)}
                      className="ml-4 px-4 py-2 border-2 border-gray-300 text-gray-700 text-sm font-medium rounded-xl hover:border-teal-500 hover:text-teal-600 transition-all"
                    >
                      ตั้งเป็นค่าเริ่มต้น
                    </button>
                  )}
                </div>
              </div>
            ))
          ) : (
            /* Empty State */
            <div className="text-center py-16">
              <svg className="w-24 h-24 mx-auto text-gray-300 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
              <p className="text-gray-500 text-lg">ยังไม่มีที่อยู่</p>
              <p className="text-gray-400 text-sm mt-2">กรุณาเพิ่มที่อยู่สำหรับการจัดส่งสินค้า (สูงสุด {MAX_ADDRESSES} ที่อยู่)</p>
            </div>
          )}
        </div>

      </div>

      {/* Add/Edit Address Modal */}
      {showAddForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            
            {/* Modal Header */}
            <div className="sticky top-0 bg-white border-b border-gray-200 px-8 py-6 flex justify-between items-center z-10">
              <div>
                <h2 className="text-2xl font-bold text-gray-800">
                  {editingId ? 'แก้ไขที่อยู่' : 'เพิ่มที่อยู่ใหม่'}
                </h2>
                {!editingId && addresses.length < MAX_ADDRESSES && (
                  <p className="text-sm text-gray-500 mt-1">
                    ที่อยู่ที่ {addresses.length + 1} จาก {MAX_ADDRESSES}
                  </p>
                )}
              </div>
              <button 
                onClick={handleCloseForm}
                className="text-gray-400 hover:text-gray-600 rounded-lg p-2 transition-colors"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleSubmit} className="p-8">
              
              {/* Row 1: ชื่อ และ โทรศัพท์ */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div>
                  <label className="block text-base font-normal text-gray-800 mb-2">
                    ชื่อ <span className="text-red-500">*</span>
                  </label>
                  <input 
                    type="text" 
                    name="recipient_name"
                    value={formData.recipient_name}
                    onChange={handleInputChange}
                    required
                    className="w-full px-4 py-3 bg-white border border-gray-300 rounded-lg text-base focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-transparent transition-all"
                    placeholder="กรุณากรอกชื่อผู้รับ"
                  />
                </div>

                <div>
                  <label className="block text-base font-normal text-gray-800 mb-2">
                    โทรศัพท์ <span className="text-red-500">*</span>
                  </label>
                  <input 
                    type="tel" 
                    name="phone_number"
                    value={formData.phone_number}
                    onChange={handleInputChange}
                    required
                    className={`w-full px-4 py-3 bg-white border rounded-lg text-base focus:outline-none focus:ring-2 transition-all ${
                      phoneError 
                        ? 'border-red-500 focus:ring-red-500' 
                        : 'border-gray-300 focus:ring-teal-500 focus:border-transparent'
                    }`}
                    placeholder="0812345678 (9-10 หลัก)"
                  />
                  {phoneError && (
                    <p className="text-red-500 text-xs mt-1 flex items-center gap-1">
                      <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                      {phoneError}
                    </p>
                  )}
                </div>
              </div>

              {/* Row 2: ที่อยู่ (Full Width) */}
              <div className="mb-6">
                <label className="block text-base font-normal text-gray-800 mb-2">
                  ที่อยู่ <span className="text-red-500">*</span>
                </label>
                <textarea 
                  rows="3"
                  name="address"
                  value={formData.address}
                  onChange={handleInputChange}
                  required
                  className="w-full px-4 py-3 bg-white border border-gray-300 rounded-lg text-base focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-transparent transition-all resize-none"
                  placeholder="บ้านเลขที่, ชื่อหมู่บ้าน, ซอย, ถนน (ไม่ต้องใส่แขวง/เขต/จังหวัด)"
                />
              </div>

              {/* Row 3: จังหวัด และ แขวง/ตำบล */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div>
                  <label className="block text-base font-normal text-gray-800 mb-2">
                    จังหวัด <span className="text-red-500">*</span>
                  </label>
                  
                  <Select
                    instanceId="province-select-address"
                    options={provinces}
                    onChange={handleProvinceChange}
                    value={provinces.find((p) => p.value === formData.province) || null}
                    placeholder="-- เลือกจังหวัด --"
                    isClearable
                    noOptionsMessage={() => 'ไม่พบจังหวัดที่ค้นหา'}
                    styles={{
                      control: (baseStyles, state) => ({
                        ...baseStyles,
                        minHeight: '50px',
                        borderColor: state.isFocused ? '#14b8a6' : '#d1d5db',
                        boxShadow: state.isFocused ? '0 0 0 2px rgba(20, 184, 166, 0.2)' : 'none',
                        '&:hover': {
                          borderColor: '#9ca3af',
                        },
                      }),
                      menu: (baseStyles) => ({
                        ...baseStyles,
                        zIndex: 50,
                      }),
                    }}
                  />
                </div>

                <div>
                  <label className="block text-base font-normal text-gray-800 mb-2">
                    แขวง/ตำบล <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="subdistrict"
                    value={formData.subdistrict}
                    onChange={handleInputChange}
                    required
                    className="w-full px-4 py-3 bg-white border border-gray-300 rounded-lg text-base focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-transparent transition-all"
                    placeholder="ระบุแขวง/ตำบล"
                  />
                </div>
              </div>

              {/* Row 4: เขต/อำเภอ และ รหัสไปรษณีย์ */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div>
                  <label className="block text-base font-normal text-gray-800 mb-2">
                    เขต/อำเภอ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="district"
                    value={formData.district}
                    onChange={handleInputChange}
                    required
                    className="w-full px-4 py-3 bg-white border border-gray-300 rounded-lg text-base focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-transparent transition-all"
                    placeholder="ระบุเขต/อำเภอ"
                  />
                </div>

                <div>
                  <label className="block text-base font-normal text-gray-800 mb-2">
                    รหัสไปรษณีย์ <span className="text-red-500">*</span>
                  </label>
                  <input 
                    type="text" 
                    name="postal_code"
                    value={formData.postal_code}
                    onChange={handleInputChange}
                    pattern="[0-9]{5}"
                    maxLength="5"
                    required
                    className="w-full px-4 py-3 bg-white border border-gray-300 rounded-lg text-base focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-transparent transition-all"
                    placeholder="10100"
                  />
                </div>
              </div>

              {/* Default Address Checkbox */}
              <div className="flex items-center mb-8">
                <input 
                  type="checkbox" 
                  id="default"
                  name="is_default"
                  checked={formData.is_default}
                  onChange={handleInputChange}
                  className="w-5 h-5 text-teal-600 border-gray-300 rounded focus:ring-teal-500"
                />
                <label htmlFor="default" className="ml-3 text-base text-gray-700">
                  ตั้งเป็นที่อยู่เริ่มต้น
                </label>
              </div>

              {/* Submit Buttons */}
              <div className="flex gap-4 pt-4 border-t border-gray-200">
                <button 
                  type="button"
                  onClick={handleCloseForm}
                  className="flex-1 px-8 py-3 bg-white border-2 border-gray-300 text-gray-700 font-medium text-base rounded-lg hover:bg-gray-50 transition-all"
                >
                  ยกเลิก
                </button>
                <button 
                  type="submit"
                  className="flex-1 px-8 py-3 bg-[#0b2f27] text-white font-medium text-base rounded-lg hover:bg-[#13493d] transition-all shadow-lg"
                >
                  {editingId ? 'บันทึกการแก้ไข' : 'บันทึก'}
                </button>
              </div>

            </form>
          </div>
        </div>
      )}

      {/* Delete Confirm Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-sm p-6">
            <p className="font-medium text-gray-800 text-lg">
              คุณต้องการลบที่อยู่นี้หรือไม่?
            </p>
            <p className="text-sm text-gray-500 mt-2">
              การลบไม่สามารถย้อนกลับได้
            </p>

            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowDeleteModal(false);
                  setDeletingId(null);
                }}
                className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200"
              >
                ยกเลิก
              </button>
              <button
                onClick={confirmDelete}
                className="px-4 py-2 bg-red-600 text-white text-sm rounded-lg hover:bg-red-700"
              >
                ยืนยัน
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default AddressForm;