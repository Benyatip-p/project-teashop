// src/components/Navbar.jsx
import React, { useState, useEffect, useRef } from 'react'
import {
  Link,
  NavLink,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import {
  ShoppingCartIcon,
  SearchIcon,
  UserIcon,
  MenuIcon,
  XIcon,
  HeartIcon,
  LogoutIcon,
} from '@heroicons/react/outline'
import axios from 'axios'
import { jwtDecode } from 'jwt-decode'
import { useShop } from '../context/ShopContext'
import SearchOverlay from './SearchOverlay'

const Navbar = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [isSearchOpen, setIsSearchOpen] = useState(false)
  const [searchText, setSearchText] = useState('')
  const [isUserDropdownOpen, setIsUserDropdownOpen] = useState(false)
  const userDropdownRef = useRef(null)

  const { cartCount } = useShop()
  const location = useLocation()
  const navigate = useNavigate()

  const isActivePath = path => location.pathname.startsWith(path)

  const desktopNavLinkClass = ({ isActive }) =>
    `text-sm font-medium tracking-wide text-emerald-50 hover:text-viridian-200 transition-colors ${
      isActive ? 'border-b-2 border-emerald-200 pb-1' : ''
    }`

  const mobileNavLinkClass =
    'block py-2 text-sm font-medium text-emerald-50 hover:text-viridian-200 transition-colors'

  const toggleMenu = () => {
    setIsMenuOpen(prev => !prev)
  }

  const openSearch = () => {
    setIsSearchOpen(true)
    setSearchText('')
  }

  const closeSearch = () => {
    setIsSearchOpen(false)
  }

  const handleSearchSubmit = query => {
    const q = query.trim()
    if (!q) return
    navigate(`/products?search=${encodeURIComponent(q)}`)
    setIsSearchOpen(false)
  }

  const isBrowser = typeof window !== 'undefined'
  let isLoggedIn = false
  let isAdmin = false
  let username = ''

  if (isBrowser) {
    const token = localStorage.getItem('access_token')
    if (token) {
      try {
        const decoded = jwtDecode(token)
        const roles = Array.isArray(decoded.roles) ? decoded.roles : []
        isLoggedIn = true
        isAdmin =
          roles.includes('admin') || roles.includes('store_manager')
        username = decoded.username || ''
      } catch (e) {
        isLoggedIn = false
        isAdmin = false
        username = ''
      }
    }
  }

  useEffect(() => {
    const handleClickOutside = event => {
      if (
        userDropdownRef.current &&
        !userDropdownRef.current.contains(event.target)
      ) {
        setIsUserDropdownOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [])

  const handleUserIconClick = () => {
    if (isLoggedIn) {
      setIsUserDropdownOpen(prev => !prev)
    } else {
      navigate('/login', { state: { from: location } })
    }
  }

  const handleLogout = async () => {
    try {
      const refreshToken = localStorage.getItem('refresh_token')
      if (refreshToken) {
        await axios.post('http://localhost:8080/auth/logout', {
          refresh_token: refreshToken,
        })
      }
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      localStorage.removeItem('adminUser')
      setIsUserDropdownOpen(false)
      navigate('/')
    }
  }

  return (
    <>
      {isSearchOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50"
          onClick={closeSearch}
        />
      )}

      {isSearchOpen && (
        <SearchOverlay
          value={searchText}
          onChange={setSearchText}
          onSubmit={handleSearchSubmit}
          onClose={closeSearch}
        />
      )}

      <nav className="sticky top-0 z-50 bg-viridian-900 shadow-lg">
        <div className="container mx-auto px-4">
          <div className="flex h-16 items-center justify-between">
            <Link to="/" className="group flex items-center space-x-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-100/10 transition-transform group-hover:scale-110">
                <img
                  src="/images/logo.svg"
                  alt="GoodTea Logo"
                  className="h-8 w-8"
                />
              </div>
              <span className="text-2xl font-bold tracking-wide text-emerald-50 transition-colors group-hover:text-emerald-200">
                GOODTEA
              </span>
            </Link>

            <div className="hidden items-center space-x-8 lg:flex">
              <NavLink to="/" className={desktopNavLinkClass}>
                หน้าแรก
              </NavLink>
              <NavLink to="/products" className={desktopNavLinkClass}>
                สินค้า
              </NavLink>
              <NavLink to="/about" className={desktopNavLinkClass}>
                เกี่ยวกับเรา
              </NavLink>
              <NavLink to="/contact" className={desktopNavLinkClass}>
                ติดต่อ
              </NavLink>
            </div>

            <div className="flex items-center space-x-3">
              {isAdmin && (
                <button
                  type="button"
                  onClick={() => navigate('/admin/dashboard')}
                  className="hidden items-center rounded-full border border-emerald-300/70 bg-emerald-100/5 px-3 py-1 text-xs font-semibold text-emerald-50 transition-colors hover:bg-emerald-100/15 hover:text-emerald-100 md:inline-flex"
                >
                  จัดการร้าน
                </button>
              )}

              <button
                type="button"
                className="p-2 text-emerald-50 transition-colors hover:text-emerald-200"
                onClick={openSearch}
              >
                <SearchIcon className="h-6 w-6" />
              </button>

              <Link
                to="/favorites"
                className={`p-2 transition-colors ${
                  isActivePath('/favorites')
                    ? 'text-emerald-300'
                    : 'text-emerald-50 hover:text-emerald-200'
                }`}
              >
                <HeartIcon className="h-6 w-6" />
              </Link>

              <Link
                to="/cart"
                className={`relative p-2 transition-colors ${
                  isActivePath('/cart')
                    ? 'text-emerald-300'
                    : 'text-emerald-50 hover:text-emerald-200'
                }`}
              >
                <ShoppingCartIcon className="h-6 w-6" />
                {cartCount > 0 && (
                  <span className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-red-500 text-xs text-white">
                    {cartCount}
                  </span>
                )}
              </Link>

              <div className="relative" ref={userDropdownRef}>
                <button
                  type="button"
                  onClick={handleUserIconClick}
                  className={`flex items-center space-x-2 p-2 transition-colors ${
                    isUserDropdownOpen
                      ? 'text-emerald-300'
                      : 'text-emerald-50 hover:text-emerald-200'
                  }`}
                >
                  <UserIcon className="h-6 w-6" />
                  {isLoggedIn && username && (
                    <span className="hidden max-w-[100px] truncate text-sm font-medium md:inline">
                      {username}
                    </span>
                  )}
                </button>

                {isLoggedIn && isUserDropdownOpen && (
                  <div className="absolute right-0 z-50 mt-2 w-48 rounded-lg bg-white shadow-lg ring-1 ring-black ring-opacity-5">
                    <div className="py-1">
                      <Link
                        to="/user/account/profile"
                        onClick={() => setIsUserDropdownOpen(false)}
                        className="flex items-center px-4 py-3 text-sm text-gray-700 transition-colors hover:bg-gray-100"
                      >
                        <UserIcon className="mr-3 h-5 w-5 text-viridian-600" />
                        บัญชีของฉัน
                      </Link>
                      <Link
                        to="/orders"
                        onClick={() => setIsUserDropdownOpen(false)}
                        className="flex items-center px-4 py-3 text-sm text-gray-700 transition-colors hover:bg-gray-100"
                      >
                        <ShoppingCartIcon className="mr-3 h-5 w-5 text-viridian-600" />
                        การซื้อของฉัน
                      </Link>
                      <hr className="my-1 border-gray-200" />
                      <button
                        type="button"
                        onClick={handleLogout}
                        className="flex w-full items-center px-4 py-3 text-sm text-red-600 transition-colors hover:bg-red-50"
                      >
                        <LogoutIcon className="mr-3 h-5 w-5" />
                        ออกจากระบบ
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <button
                type="button"
                className="p-2 text-emerald-50 transition-colors hover:text-emerald-200 lg:hidden"
                onClick={toggleMenu}
              >
                {isMenuOpen ? (
                  <XIcon className="h-6 w-6" />
                ) : (
                  <MenuIcon className="h-6 w-6" />
                )}
              </button>
            </div>
          </div>

          <div
            className={`transition-all duration-300 ease-in-out lg:hidden ${
              isMenuOpen
                ? 'max-h-64 opacity-100'
                : 'max-h-0 overflow-hidden opacity-0'
            }`}
          >
            <div className="border-t border-emerald-800 py-4">
              <NavLink
                to="/"
                className={mobileNavLinkClass}
                onClick={() => setIsMenuOpen(false)}
              >
                หน้าแรก
              </NavLink>
              <NavLink
                to="/products"
                className={mobileNavLinkClass}
                onClick={() => setIsMenuOpen(false)}
              >
                สินค้า
              </NavLink>
              <NavLink
                to="/categories"
                className={mobileNavLinkClass}
                onClick={() => setIsMenuOpen(false)}
              >
                หมวดหมู่
              </NavLink>
              <NavLink
                to="/about"
                className={mobileNavLinkClass}
                onClick={() => setIsMenuOpen(false)}
              >
                เกี่ยวกับเรา
              </NavLink>
              <NavLink
                to="/contact"
                className={mobileNavLinkClass}
                onClick={() => setIsMenuOpen(false)}
              >
                ติดต่อ
              </NavLink>

              {isAdmin && (
                <button
                  type="button"
                  onClick={() => {
                    setIsMenuOpen(false)
                    navigate('/admin/dashboard')
                  }}
                  className="mt-2 w-full rounded-md bg-emerald-600 py-2 text-center text-sm font-semibold text-white transition-colors hover:bg-emerald-700"
                >
                  จัดการร้าน
                </button>
              )}
            </div>
          </div>
        </div>
      </nav>
    </>
  )
}

export default Navbar
