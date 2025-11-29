import React, { useState, useRef, useEffect } from 'react';
import { useLocation, Link, useNavigate } from 'react-router-dom';
import api from '../api/api';

import {
  UserIcon,
  PencilIcon,
  ClipboardListIcon,
  ChevronDownIcon,
  ChevronUpIcon
} from '@heroicons/react/outline';

const SidebarProfile = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [isAccountOpen, setIsAccountOpen] = useState(true);
  const [user, setUser] = useState({ username: '' });
  const sidebarRef = useRef(null);

  // Define menu items with their paths
  const accountSubMenus = [
    { id: 'profile', label: 'ประวัติ', path: '/user/account/profile' },
    { id: 'address', label: 'ที่อยู่', path: '/user/account/address' },
  ];

  // Check if a path is active
  const isActive = (path) => location.pathname === path;

  // Check if any account-related page is active
  const isAccountSectionActive = ['/user/account/profile', '/user/account/address'].includes(location.pathname);

  // Fetch user profile data
  const fetchProfile = async () => {
    try {
      const response = await api.get('/profile');
      setUser(response.data);
    } catch (error) {
      console.error('Failed to fetch profile:', error);
    }
  };

  // Set initial accordion state based on current route
  useEffect(() => {
    const accountPaths = ['/user/account/profile', '/user/account/address'];
    if (location.pathname === '/user/purchase') {
      setIsAccountOpen(false);
    } else if (accountPaths.includes(location.pathname)) {
      setIsAccountOpen(true);
    }
  }, [location.pathname]);

  // Fetch user profile on component mount
  useEffect(() => {
    fetchProfile();
  }, []);

  // Click outside handler
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (sidebarRef.current && !sidebarRef.current.contains(event.target)) {
        setIsAccountOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  return (
    <aside ref={sidebarRef} className="w-full flex-none rounded-xl bg-white p-5 shadow-sm md:w-64 lg:w-72 md:sticky md:top-24 md:self-start">
      {/* User Info Header */}
      <div className="flex items-center gap-3 mb-6 pb-4 border-b border-gray-200">
        <div className="w-12 h-12 rounded-full bg-gray-100 flex items-center justify-center text-viridian-600 border border-gray-200">
          <UserIcon className="h-7 w-7" />
        </div>
        <div className="flex flex-col">
          <span className="font-semibold text-gray-900 truncate">{user.username}</span>
          <Link
            to="/user/account/profile"
            className="text-gray-600 text-sm flex items-center gap-1 hover:text-viridian-600 transition-colors"
          >
            <PencilIcon className="h-3 w-3 text-viridian-600" />
            แก้ไขข้อมูลส่วนตัว
          </Link>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav className="space-y-1">

        {/* My Account Accordion */}
        <div className="pt-4 mt-4">
          <button
            onClick={() => {
              setIsAccountOpen(!isAccountOpen);
              navigate('/user/account/profile');
            }}
            className={`w-full text-left text-sm font-semibold px-2 py-1.5 rounded-lg flex items-center justify-between ${
              (isAccountSectionActive && location.pathname === '/user/account/profile') || location.pathname === '/user/purchase'
                ? 'bg-viridian-50 text-viridian-700'
                : 'text-gray-900 hover:bg-gray-100'
            }`}
          >
            <div className="flex items-center gap-2">
              <UserIcon className="h-5 w-5 text-viridian-600" />
              <span>บัญชีของฉัน</span>
            </div>
            {isAccountOpen ? (
              <ChevronUpIcon className="h-4 w-4" />
            ) : (
              <ChevronDownIcon className="h-4 w-4" />
            )}
          </button>

          {/* Sub-menu items */}
          <div
            className={`overflow-hidden transition-all duration-300 ease-in-out ${
              isAccountOpen ? 'max-h-48 opacity-100' : 'max-h-0 opacity-0'
            }`}
          >
            <div className="mt-2 space-y-1 pl-4">
              {accountSubMenus.map((item) => (
                <Link
                  key={item.id}
                  to={item.path}
                  className={`w-full text-left text-sm px-2 py-1.5 rounded-lg block transition-colors ${
                    isActive(item.path)
                      ? 'bg-viridian-600 text-white'
                      : 'text-gray-700 hover:bg-gray-100'
                  }`}
                >
                  {item.label}
                </Link>
              ))}
            </div>
          </div>
        </div>

        {/* My Purchases Link */}
        <button
          onClick={() => {
            setIsAccountOpen(false);
            navigate('/user/purchase');
          }}
          className={`w-full text-left text-sm font-semibold px-3 py-2 rounded-lg flex items-center gap-2 transition-colors ${
            location.pathname === '/user/purchase'
              ? 'bg-viridian-600 text-white'
              : 'text-gray-700 hover:bg-gray-100'
          }`}
        >
          <ClipboardListIcon className="h-5 w-5" />
          <span>การซื้อของฉัน</span>
        </button>

      </nav>
    </aside>
  );
};

export default SidebarProfile;